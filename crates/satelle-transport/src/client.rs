use crate::contract::{
    ApiError, ApiErrorCode, AuthenticatedResponseContract, CapabilitiesResponse,
    HostDesktopSessionsResponse, HostStatusResponse, LiveResponse, LogsPageResponse,
    PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER, RequestId, SessionResponse, StopRequest,
    StopResponse, TurnRequest,
};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Method, StatusCode};
use satelle_core::SessionId;
use satelle_host::{ApiBearerToken, LogPageQuery};
use serde::de::DeserializeOwned;
use std::fmt;
use std::net::SocketAddr;
use zeroize::Zeroizing;

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

    pub fn live(&self) -> Result<LiveResponse, DaemonClientError> {
        let response = self
            .client
            .get(format!("{}/v1/live", self.base_url))
            .send()
            .map_err(DaemonClientError::Transport)?;
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
        let response = request.send().map_err(DaemonClientError::Transport)?;
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
            Self::Transport(error) | Self::InvalidResponse(error) => Some(error),
            _ => None,
        }
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
#[path = "client-events.rs"]
mod events;

pub use events::{DaemonEventClient, DaemonEventError, DaemonEventStream};
