use crate::contract::{
    ApiError, ApiErrorCode, AuthenticatedResponseContract, CapabilitiesResponse,
    HostDesktopSessionsResponse, HostStatusResponse, LiveResponse, LogsPageResponse,
    PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER, RequestId, SessionResponse, StopRequest,
    StopResponse, TurnRequest,
};
use crate::transport_tls::{
    ReqwestTrustError, TlsFailureKind, classify_tls_error, configure_reqwest_trust,
    find_error_in_tree,
};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Method, StatusCode};
use satelle_core::{DirectHostBinding, SessionId};
use satelle_host::{ApiBearerToken, LogPageQuery};
use serde::de::DeserializeOwned;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;
use zeroize::Zeroizing;

const DIRECT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct DaemonClient {
    client: Client,
    base_url: String,
    token: ApiBearerToken,
    expected_host_identity: String,
}

impl DaemonClient {
    pub fn loopback(
        address: SocketAddr,
        token: ApiBearerToken,
        expected_host_identity: impl Into<String>,
    ) -> Result<Self, DaemonClientError> {
        if !address.ip().is_loopback() {
            return Err(DaemonClientError::NonLoopbackPlaintextEndpoint);
        }
        let expected_host_identity = expected_host_identity.into();
        HeaderValue::from_str(&expected_host_identity)
            .map_err(|_| DaemonClientError::InvalidHostIdentityHeader)?;
        let client = Client::builder()
            .redirect(Policy::none())
            .build()
            .map_err(DaemonClientError::Transport)?;
        Ok(Self {
            client,
            base_url: format!("http://{address}"),
            token,
            expected_host_identity,
        })
    }

    pub fn https(
        binding: &DirectHostBinding,
        token: ApiBearerToken,
        ca_bundle: Option<&[u8]>,
    ) -> Result<Self, DaemonClientError> {
        Self::https_with_timeout(binding, token, ca_bundle, DIRECT_REQUEST_TIMEOUT)
    }

    fn https_with_timeout(
        binding: &DirectHostBinding,
        token: ApiBearerToken,
        ca_bundle: Option<&[u8]>,
        request_timeout: Duration,
    ) -> Result<Self, DaemonClientError> {
        let expected_host_identity = binding.expected_host_identity().to_string();
        HeaderValue::from_str(&expected_host_identity)
            .map_err(|_| DaemonClientError::InvalidHostIdentityHeader)?;
        let builder = Client::builder()
            .redirect(Policy::none())
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .timeout(request_timeout);
        let builder = configure_reqwest_trust(builder, ca_bundle).map_err(|error| match error {
            ReqwestTrustError::InvalidCaBundle(error) => DaemonClientError::InvalidCaBundle(error),
            ReqwestTrustError::EmptyCaBundle => DaemonClientError::EmptyCaBundle,
        })?;
        let client = builder.build().map_err(DaemonClientError::Transport)?;
        Ok(Self {
            client,
            base_url: binding.origin().to_string(),
            token,
            expected_host_identity,
        })
    }

    pub fn live(&self) -> Result<LiveResponse, DaemonClientError> {
        let response = self
            .client
            .get(format!("{}/v1/live", self.base_url))
            .send()
            .map_err(classify_request_error)?;
        decode_unpinned(response, StatusCode::OK)
    }

    pub fn capabilities(&self) -> Result<CapabilitiesResponse, DaemonClientError> {
        let (request, request_id) = self.protected_request(Method::GET, "/v1/capabilities")?;
        self.send_authenticated(request, request_id, StatusCode::OK)
    }

    pub fn host_status(&self) -> Result<HostStatusResponse, DaemonClientError> {
        let (request, request_id) = self.protected_request(Method::GET, "/v1/host/status")?;
        self.send_authenticated(request, request_id, StatusCode::OK)
    }

    pub fn desktop_sessions(&self) -> Result<HostDesktopSessionsResponse, DaemonClientError> {
        let (request, request_id) =
            self.protected_request(Method::GET, "/v1/host/desktop-sessions")?;
        self.send_authenticated(request, request_id, StatusCode::OK)
    }

    pub fn logs(&self, query: &LogPageQuery) -> Result<LogsPageResponse, DaemonClientError> {
        let (request, request_id) = self.protected_request(Method::GET, "/v1/logs")?;
        self.send_authenticated(request.query(query), request_id, StatusCode::OK)
    }

    pub fn create_session(
        &self,
        request: &TurnRequest,
        idempotency_key: &str,
    ) -> Result<SessionResponse, DaemonClientError> {
        let (request_builder, request_id) =
            self.mutation_request("/v1/sessions", idempotency_key)?;
        self.send_authenticated(
            request_builder.json(request),
            request_id,
            StatusCode::ACCEPTED,
        )
    }

    pub fn create_turn(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
        idempotency_key: &str,
    ) -> Result<SessionResponse, DaemonClientError> {
        let path = format!("/v1/sessions/{session_id}/turns");
        let (request_builder, request_id) = self.mutation_request(&path, idempotency_key)?;
        self.send_authenticated(
            request_builder.json(request),
            request_id,
            StatusCode::ACCEPTED,
        )
    }

    pub fn read_session(
        &self,
        session_id: &SessionId,
    ) -> Result<SessionResponse, DaemonClientError> {
        let path = format!("/v1/sessions/{session_id}");
        let (request, request_id) = self.protected_request(Method::GET, &path)?;
        self.send_authenticated(request, request_id, StatusCode::OK)
    }

    pub fn stop_session(
        &self,
        session_id: &SessionId,
        idempotency_key: &str,
    ) -> Result<StopResponse, DaemonClientError> {
        let path = format!("/v1/sessions/{session_id}/stop");
        let (request, request_id) = self.mutation_request(&path, idempotency_key)?;
        self.send_authenticated(
            request.json(&StopRequest::new()),
            request_id,
            StatusCode::OK,
        )
    }

    fn mutation_request(
        &self,
        path: &str,
        idempotency_key: &str,
    ) -> Result<(RequestBuilder, RequestId), DaemonClientError> {
        let mut header = HeaderValue::from_str(idempotency_key)
            .map_err(|_| DaemonClientError::InvalidIdempotencyKeyHeader)?;
        header.set_sensitive(true);
        let (request, request_id) = self.protected_request(Method::POST, path)?;
        Ok((
            request
                .header("Idempotency-Key", header)
                .header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION),
            request_id,
        ))
    }

    fn protected_request(
        &self,
        method: Method,
        path: &str,
    ) -> Result<(RequestBuilder, RequestId), DaemonClientError> {
        let exposed = self.token.expose();
        let authorization_value = Zeroizing::new(format!("Bearer {}", exposed.as_str()));
        let mut authorization = HeaderValue::from_str(authorization_value.as_str())
            .map_err(|_| DaemonClientError::InvalidTokenHeader)?;
        authorization.set_sensitive(true);
        let request_id = RequestId::new();
        let request = self
            .client
            .request(method, format!("{}{path}", self.base_url))
            .header(AUTHORIZATION, authorization)
            .header(
                "Satelle-Expected-Host-Identity",
                &self.expected_host_identity,
            )
            .header("Satelle-Request-Id", request_id.to_string());
        Ok((request, request_id))
    }

    fn send_authenticated<T: DeserializeOwned + AuthenticatedResponseContract>(
        &self,
        request: RequestBuilder,
        request_id: RequestId,
        expected_status: StatusCode,
    ) -> Result<T, DaemonClientError> {
        let response = request.send().map_err(classify_request_error)?;
        decode_authenticated(
            response,
            expected_status,
            &request_id,
            &self.expected_host_identity,
        )
    }
}

impl fmt::Debug for DaemonClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonClient")
            .field("base_url", &self.base_url)
            .field("expected_host_identity", &self.expected_host_identity)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum DaemonClientError {
    NonLoopbackPlaintextEndpoint,
    InvalidTokenHeader,
    InvalidHostIdentityHeader,
    InvalidIdempotencyKeyHeader,
    InvalidCaBundle(reqwest::Error),
    EmptyCaBundle,
    CertificateUntrusted(reqwest::Error),
    CertificateHostnameMismatch(reqwest::Error),
    CertificateExpired(reqwest::Error),
    TlsVersionUnsupported(reqwest::Error),
    TlsHandshake(reqwest::Error),
    Transport(reqwest::Error),
    InvalidResponse(reqwest::Error),
    Api {
        status: StatusCode,
        error: Box<ApiError>,
    },
    UnexpectedSuccessStatus {
        expected: StatusCode,
        actual: StatusCode,
    },
    ResponseRequestIdMismatch,
    ResponseHostIdentityMismatch,
}

impl fmt::Display for DaemonClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonLoopbackPlaintextEndpoint => {
                "plaintext Host Daemon transport requires a loopback endpoint"
            }
            Self::InvalidTokenHeader => "the Host Daemon bearer token cannot form a header",
            Self::InvalidHostIdentityHeader => {
                "the expected Host Identity cannot form a request header"
            }
            Self::InvalidIdempotencyKeyHeader => "the idempotency key cannot form a request header",
            Self::InvalidCaBundle(_) => "the configured CA bundle is invalid",
            Self::EmptyCaBundle => "the configured CA bundle contains no certificates",
            Self::CertificateUntrusted(_) => "the Host Daemon certificate is not trusted",
            Self::CertificateHostnameMismatch(_) => {
                "the Host Daemon certificate does not match the configured hostname"
            }
            Self::CertificateExpired(_) => "the Host Daemon certificate has expired",
            Self::TlsVersionUnsupported(_) => "the Host Daemon does not support TLS 1.2 or newer",
            Self::TlsHandshake(_) => "the Host Daemon TLS handshake failed",
            Self::Transport(_) => "the Host Daemon request failed",
            Self::InvalidResponse(_) => "the Host Daemon returned an invalid response",
            Self::Api { .. } => "the Host Daemon rejected the request",
            Self::UnexpectedSuccessStatus { .. } => {
                "the Host Daemon returned an unexpected success status"
            }
            Self::ResponseRequestIdMismatch => {
                "the Host Daemon response did not match the request ID"
            }
            Self::ResponseHostIdentityMismatch => {
                "the Host Daemon response did not match the pinned Host Identity"
            }
        })
    }
}

impl std::error::Error for DaemonClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCaBundle(error)
            | Self::CertificateUntrusted(error)
            | Self::CertificateHostnameMismatch(error)
            | Self::CertificateExpired(error)
            | Self::TlsVersionUnsupported(error)
            | Self::TlsHandshake(error)
            | Self::Transport(error)
            | Self::InvalidResponse(error) => Some(error),
            _ => None,
        }
    }
}

fn classify_request_error(error: reqwest::Error) -> DaemonClientError {
    match find_error_in_tree::<rustls::Error>(&error, 16).map(classify_tls_error) {
        Some(TlsFailureKind::CertificateUntrusted) => {
            DaemonClientError::CertificateUntrusted(error)
        }
        Some(TlsFailureKind::CertificateHostnameMismatch) => {
            DaemonClientError::CertificateHostnameMismatch(error)
        }
        Some(TlsFailureKind::CertificateExpired) => DaemonClientError::CertificateExpired(error),
        Some(TlsFailureKind::VersionUnsupported) => DaemonClientError::TlsVersionUnsupported(error),
        Some(TlsFailureKind::Handshake) => DaemonClientError::TlsHandshake(error),
        None => DaemonClientError::Transport(error),
    }
}

fn decode_unpinned<T: DeserializeOwned>(
    response: Response,
    expected_status: StatusCode,
) -> Result<T, DaemonClientError> {
    let actual = response.status();
    if actual == expected_status {
        return response.json().map_err(DaemonClientError::InvalidResponse);
    }
    if actual.is_success() {
        return Err(DaemonClientError::UnexpectedSuccessStatus {
            expected: expected_status,
            actual,
        });
    }
    let error = response
        .json::<ApiError>()
        .map_err(DaemonClientError::InvalidResponse)?;
    Err(DaemonClientError::Api {
        status: actual,
        error: Box::new(error),
    })
}

fn decode_authenticated<T: DeserializeOwned + AuthenticatedResponseContract>(
    response: Response,
    expected_status: StatusCode,
    request_id: &RequestId,
    expected_host_identity: &str,
) -> Result<T, DaemonClientError> {
    let actual = response.status();
    if actual == expected_status {
        let value = response
            .json::<T>()
            .map_err(DaemonClientError::InvalidResponse)?;
        validate_response_context(&value, request_id, expected_host_identity)?;
        return Ok(value);
    }
    if actual.is_success() {
        return Err(DaemonClientError::UnexpectedSuccessStatus {
            expected: expected_status,
            actual,
        });
    }
    let error = response
        .json::<ApiError>()
        .map_err(DaemonClientError::InvalidResponse)?;
    if error.request_id() != request_id {
        return Err(DaemonClientError::ResponseRequestIdMismatch);
    }
    if !api_error_host_identity_is_valid(&error, expected_host_identity) {
        return Err(DaemonClientError::ResponseHostIdentityMismatch);
    }
    Err(DaemonClientError::Api {
        status: actual,
        error: Box::new(error),
    })
}

pub(super) fn api_error_host_identity_is_valid(
    error: &ApiError,
    expected_host_identity: &str,
) -> bool {
    match error.code() {
        // Authentication failures and the failed-authentication limiter run
        // before the server is allowed to reveal Host metadata.
        ApiErrorCode::AuthenticationFailed => error.host_identity().is_none(),
        ApiErrorCode::RateLimited => error
            .host_identity()
            .is_none_or(|identity| identity == expected_host_identity),
        // A mismatch response must identify the Host that was actually
        // reached, which is intentionally allowed to differ from the pin.
        ApiErrorCode::HostIdentityMismatch => error.host_identity().is_some(),
        _ => error.host_identity() == Some(expected_host_identity),
    }
}

fn validate_response_context(
    response: &impl AuthenticatedResponseContract,
    request_id: &RequestId,
    expected_host_identity: &str,
) -> Result<(), DaemonClientError> {
    if response.request_id() != request_id {
        return Err(DaemonClientError::ResponseRequestIdMismatch);
    }
    if response.host_identity() != expected_host_identity {
        return Err(DaemonClientError::ResponseHostIdentityMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use satelle_core::{
        ApiTokenSource, DirectHostBindingError, HostConfig, SatelleConfig, TransportKind,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    #[test]
    fn direct_client_accepts_only_a_canonical_https_origin() {
        let binding =
            direct_binding("https://windows.example.test/").expect("construct direct Host Binding");
        let client = DaemonClient::https(
            &binding,
            ApiBearerToken::generate().expect("generate token"),
            None,
        )
        .expect("construct HTTPS client");
        let debug = format!("{client:?}");
        assert!(debug.contains("https://windows.example.test"));
        assert!(!debug.contains(client.token.expose().as_str()));

        assert!(matches!(
            DaemonClient::https(
                &binding,
                ApiBearerToken::generate().expect("generate token"),
                Some(b"-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----\n"),
            ),
            Err(DaemonClientError::InvalidCaBundle(_))
        ));
        assert!(matches!(
            DaemonClient::https(
                &binding,
                ApiBearerToken::generate().expect("generate token"),
                Some(b""),
            ),
            Err(DaemonClientError::EmptyCaBundle)
        ));

        assert!(matches!(
            direct_binding("http://windows.example.test"),
            Err(DirectHostBindingError::InsecureOrigin)
        ));
        for endpoint in [
            "https://user@windows.example.test",
            "https://windows.example.test/v1",
            "https://windows.example.test?redirect=1",
            "not-a-url",
        ] {
            assert!(matches!(
                direct_binding(endpoint),
                Err(DirectHostBindingError::InvalidHttpsOrigin)
            ));
        }

        let mut config = direct_host_config("https://windows.example.test");
        config.api_token = Some(ApiTokenSource::File {
            path: "relative.token".into(),
        });
        assert_eq!(
            DirectHostBinding::from_host_config(&config),
            Err(DirectHostBindingError::InvalidApiTokenPath)
        );
        let mut config = direct_host_config("https://windows.example.test");
        config.ca_bundle = Some("~/satelle-ca.pem".into());
        assert_eq!(
            DirectHostBinding::from_host_config(&config),
            Err(DirectHostBindingError::InvalidCaBundlePath)
        );
    }

    #[test]
    fn direct_client_distinguishes_tls_failures_from_unreachable_hosts() {
        let unreachable = TcpListener::bind("127.0.0.1:0").expect("bind temporary port");
        let unreachable_address = unreachable.local_addr().expect("read temporary address");
        drop(unreachable);
        let binding = direct_binding(&format!("https://{unreachable_address}"))
            .expect("construct unreachable binding");
        let client = DaemonClient::https(
            &binding,
            ApiBearerToken::generate().expect("generate token"),
            None,
        )
        .expect("construct HTTPS client");
        assert!(matches!(
            client.host_status(),
            Err(DaemonClientError::Transport(_))
        ));

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind plaintext server");
        let plaintext_address = listener.local_addr().expect("read plaintext address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept TLS client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set server timeout");
            read_tls_record(&mut stream);
            finish_tls_fixture_response(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            );
        });
        let binding = direct_binding(&format!("https://{plaintext_address}"))
            .expect("construct plaintext binding");
        let client = DaemonClient::https(
            &binding,
            ApiBearerToken::generate().expect("generate token"),
            None,
        )
        .expect("construct HTTPS client");
        let error = client
            .host_status()
            .expect_err("plaintext response must fail TLS");
        assert!(
            matches!(error, DaemonClientError::TlsHandshake(_)),
            "unexpected error: {error:?}"
        );
        server.join().expect("join plaintext server");
    }

    #[test]
    fn direct_client_completes_a_pinned_authenticated_https_request() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("generate test certificate");
        let certificate_der = cert.der().clone();
        let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der.clone()], private_key.into())
            .expect("configure TLS server");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS server");
        let address = listener.local_addr().expect("read TLS server address");
        let token = ApiBearerToken::generate().expect("generate token");
        let expected_authorization = Zeroizing::new(format!("Bearer {}", token.expose().as_str()));
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept HTTPS client");
            let connection = rustls::ServerConnection::new(Arc::new(server_config))
                .expect("create TLS server connection");
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).expect("read HTTPS request");
                assert_ne!(read, 0, "HTTPS request ended before its headers");
                request.extend_from_slice(&chunk[..read]);
            }
            let request = String::from_utf8(request).expect("request headers should be UTF-8");
            assert!(request.starts_with("GET /v1/host/status HTTP/1.1\r\n"));
            assert_eq!(
                header_value(&request, "authorization"),
                Some(expected_authorization.as_str())
            );
            assert_eq!(
                header_value(&request, "satelle-expected-host-identity"),
                Some("host-windows-11")
            );
            let request_id = header_value(&request, "satelle-request-id")
                .expect("request must carry a request ID");
            let body = format!(
                "{{\"schema_version\":\"satelle.host.status.v1\",\"request_id\":\"{request_id}\",\"host_identity\":\"host-windows-11\",\"daemon_version\":\"0.1.0\",\"started_at\":\"2024-01-01T00:00:00Z\",\"process_mode\":\"foreground\",\"session_count\":3,\"active_turn_count\":0,\"recovery_pending_turn_count\":0}}"
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("write HTTPS response");
            stream.flush().expect("flush HTTPS response");
        });

        let binding = direct_binding(&format!("https://localhost:{}", address.port()))
            .expect("construct trusted TLS binding");
        let certificate_pem = cert.pem();
        let daemon = DaemonClient::https(&binding, token, Some(certificate_pem.as_bytes()))
            .expect("construct trusted HTTPS client");
        let response = daemon.host_status().expect("complete HTTPS Host status");
        assert_eq!(response.host_identity(), "host-windows-11");
        assert_eq!(response.session_count(), 3);
        server.join().expect("join TLS server");
    }

    #[test]
    fn direct_client_bounds_stalled_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled TLS server");
        let address = listener.local_addr().expect("read stalled server address");
        let server = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept stalled TLS client");
            std::thread::sleep(Duration::from_millis(200));
        });
        let binding =
            direct_binding(&format!("https://{address}")).expect("construct stalled TLS binding");
        let client = DaemonClient::https_with_timeout(
            &binding,
            ApiBearerToken::generate().expect("generate token"),
            None,
            Duration::from_millis(50),
        )
        .expect("construct bounded HTTPS client");
        let error = client
            .host_status()
            .expect_err("stalled request must reach its deadline");
        assert!(
            matches!(&error, DaemonClientError::Transport(source) if source.is_timeout()),
            "unexpected error: {error:?}"
        );
        server.join().expect("join stalled TLS server");
    }

    #[test]
    fn direct_client_reports_typed_certificate_failures_from_real_tls() {
        let (address, _certificate_pem, server) = spawn_handshake_tls_server();
        let binding = direct_binding(&format!("https://localhost:{}", address.port()))
            .expect("construct untrusted TLS binding");
        let client = DaemonClient::https(
            &binding,
            ApiBearerToken::generate().expect("generate token"),
            None,
        )
        .expect("construct untrusted HTTPS client");
        assert!(matches!(
            client.host_status(),
            Err(DaemonClientError::CertificateUntrusted(_))
        ));
        server.join().expect("join untrusted TLS server");

        let (address, certificate_pem, server) = spawn_handshake_tls_server();
        let binding = direct_binding(&format!("https://127.0.0.1:{}", address.port()))
            .expect("construct hostname-mismatch binding");
        let client = DaemonClient::https(
            &binding,
            ApiBearerToken::generate().expect("generate token"),
            Some(certificate_pem.as_bytes()),
        )
        .expect("construct hostname-mismatch HTTPS client");
        assert!(matches!(
            client.host_status(),
            Err(DaemonClientError::CertificateHostnameMismatch(_))
        ));
        server.join().expect("join hostname-mismatch TLS server");

        let mut ca_params =
            rcgen::CertificateParams::new(Vec::new()).expect("CA certificate params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        let ca_key = rcgen::KeyPair::generate().expect("generate CA key");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("generate CA certificate");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("certificate params");
        params.not_before = rcgen::date_time_ymd(2019, 1, 1);
        params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        let signing_key = rcgen::KeyPair::generate().expect("generate expired certificate key");
        let cert = params
            .signed_by(&signing_key, &issuer)
            .expect("generate expired certificate");
        let (address, certificate_pem, server) =
            spawn_tls_handshake_server(vec![cert.der().clone()], signing_key, ca_cert.pem());
        let binding = direct_binding(&format!("https://localhost:{}", address.port()))
            .expect("construct expired-certificate binding");
        let client = DaemonClient::https(
            &binding,
            ApiBearerToken::generate().expect("generate token"),
            Some(certificate_pem.as_bytes()),
        )
        .expect("construct expired-certificate HTTPS client");
        let error = client
            .host_status()
            .expect_err("expired leaf certificate must fail TLS");
        assert!(
            matches!(error, DaemonClientError::CertificateExpired(_)),
            "unexpected error: {error:?}"
        );
        server.join().expect("join expired-certificate TLS server");
    }

    #[test]
    fn direct_client_reports_an_unsupported_tls_version_alert() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS alert server");
        let address = listener
            .local_addr()
            .expect("read TLS alert server address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept TLS client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set TLS alert timeout");
            read_tls_record(&mut stream);
            // Fatal protocol_version alert in a TLS record. This is the wire
            // response an endpoint limited to an unsupported version sends.
            finish_tls_fixture_response(&mut stream, &[21, 3, 3, 0, 2, 2, 70]);
        });
        let binding =
            direct_binding(&format!("https://{address}")).expect("construct TLS-version binding");
        let client = DaemonClient::https(
            &binding,
            ApiBearerToken::generate().expect("generate token"),
            None,
        )
        .expect("construct TLS-version client");
        let error = client
            .host_status()
            .expect_err("protocol-version alert must fail");
        assert!(
            matches!(error, DaemonClientError::TlsVersionUnsupported(_)),
            "unexpected error: {error:?}"
        );
        server.join().expect("join TLS alert server");
    }

    fn spawn_handshake_tls_server() -> (std::net::SocketAddr, String, std::thread::JoinHandle<()>) {
        let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate test certificate");
        spawn_tls_handshake_server_with_key(certified_key)
    }

    fn spawn_tls_handshake_server_with_key(
        certified_key: rcgen::CertifiedKey<rcgen::KeyPair>,
    ) -> (std::net::SocketAddr, String, std::thread::JoinHandle<()>) {
        let rcgen::CertifiedKey { cert, signing_key } = certified_key;
        let certificate_pem = cert.pem();
        spawn_tls_handshake_server(vec![cert.der().clone()], signing_key, certificate_pem)
    }

    fn spawn_tls_handshake_server(
        certificate_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        signing_key: rcgen::KeyPair,
        trusted_ca_pem: String,
    ) -> (std::net::SocketAddr, String, std::thread::JoinHandle<()>) {
        let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificate_chain, private_key.into())
            .expect("configure TLS server");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS server");
        let address = listener.local_addr().expect("read TLS server address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept HTTPS client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set TLS server timeout");
            let mut connection = rustls::ServerConnection::new(Arc::new(server_config))
                .expect("create TLS server connection");
            while connection.is_handshaking() {
                if connection.complete_io(&mut stream).is_err() {
                    break;
                }
            }
        });
        (address, trusted_ca_pem, server)
    }

    fn read_tls_record(stream: &mut impl Read) {
        let mut header = [0_u8; 5];
        stream
            .read_exact(&mut header)
            .expect("read TLS record header");
        let payload_length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        assert!(
            payload_length <= 18 * 1024,
            "test TLS record exceeds the protocol limit"
        );
        let mut payload = vec![0_u8; payload_length];
        stream
            .read_exact(&mut payload)
            .expect("read complete TLS record");
    }

    fn finish_tls_fixture_response(stream: &mut std::net::TcpStream, response: &[u8]) {
        stream
            .write_all(response)
            .expect("write TLS fixture response");
        stream.flush().expect("flush TLS fixture response");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("finish TLS fixture response");
        let mut drain = [0_u8; 1024];
        while stream.read(&mut drain).is_ok_and(|read| read != 0) {}
    }

    fn header_value<'request>(request: &'request str, name: &str) -> Option<&'request str> {
        request.lines().find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    fn direct_binding(endpoint: &str) -> Result<DirectHostBinding, DirectHostBindingError> {
        DirectHostBinding::from_host_config(&direct_host_config(endpoint))
    }

    fn direct_host_config(endpoint: &str) -> HostConfig {
        let mut config = SatelleConfig::defaults()
            .hosts
            .remove("local-demo")
            .expect("default local Host config");
        config.transport = TransportKind::Direct;
        config.address = Some(endpoint.to_string());
        config.expected_host_id = Some("host-windows-11".to_string());
        config.api_token = Some(ApiTokenSource::File {
            path: std::env::temp_dir().join("satelle.token"),
        });
        config
    }
}
#[path = "client-events.rs"]
mod events;

pub use events::{DaemonEventClient, DaemonEventError, DaemonEventStream};
