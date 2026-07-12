mod api_json;
mod auth;
mod events;
mod host_error;
mod listener;
mod logs;
mod sessions;

use crate::contract::{
    ApiError, ApiErrorCategory, ApiErrorCode, CapabilitiesResponse, EffectiveLimits,
    HostDesktopSessionsResponse, HostStatusResponse, LiveResponse, RequestId, effective_limits,
};
use auth::{AuthorizedRequest, REQUEST_ID_HEADER};
use axum::Router;
use axum::extract::connect_info::Connected;
use axum::extract::{Extension, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::serve::IncomingStream;
use listener::LimitedTcpListener;
use satelle_host::{DaemonRuntimeCapabilities, HostService};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

const DEFAULT_MAX_CONNECTIONS: usize = 128;
const HOST_IDENTITY_HEADER: &str = "satelle-host-identity";
const FAILED_AUTH_LIMIT: usize = 10;
const READ_LIMIT: usize = 600;
const CONTROL_LIMIT: usize = 120;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_RATE_KEYS: usize = 4096;
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonServerConfig {
    bind_addr: SocketAddr,
    max_connections: usize,
    shutdown_grace: Duration,
}

impl DaemonServerConfig {
    pub const fn loopback(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }

    pub const fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    pub const fn with_shutdown_grace(mut self, shutdown_grace: Duration) -> Self {
        self.shutdown_grace = shutdown_grace;
        self
    }
}

pub struct DaemonServer {
    local_addr: SocketAddr,
    shutdown: Option<watch::Sender<bool>>,
    task: Option<JoinHandle<Result<(), std::io::Error>>>,
    shutdown_grace: Duration,
    shutdown_service: HostService,
}

impl DaemonServer {
    pub async fn bind(
        service: HostService,
        config: DaemonServerConfig,
    ) -> Result<Self, DaemonServerError> {
        if !config.bind_addr.ip().is_loopback() {
            return Err(DaemonServerError::NonLoopbackPlaintextBind);
        }
        if config.max_connections == 0 {
            return Err(DaemonServerError::InvalidConnectionLimit);
        }
        if config.shutdown_grace.is_zero() {
            return Err(DaemonServerError::InvalidShutdownGrace);
        }
        let initialized = service
            .initialize_daemon()
            .map_err(|_| DaemonServerError::HostInitializationFailed)?;
        let capabilities = service
            .daemon_runtime_capabilities()
            .map_err(|_| DaemonServerError::HostInitializationFailed)?;
        let listener = TcpListener::bind(config.bind_addr)
            .await
            .map_err(DaemonServerError::BindFailed)?;
        let local_addr = listener
            .local_addr()
            .map_err(DaemonServerError::BindFailed)?;
        let shutdown_service = service.clone();
        let limits = effective_limits(config.max_connections);
        let (shutdown, mut receiver) = watch::channel(false);
        let state = Arc::new(DaemonState {
            service: Arc::new(service),
            host_identity: initialized.host_identity().to_string(),
            started_at: OffsetDateTime::now_utc(),
            capabilities,
            limits,
            failed_auth_limit: FailedAuthLimiter::new(),
            authenticated_limit: FixedWindowLimiter::new(READ_LIMIT),
            control_limit: FixedWindowLimiter::new(CONTROL_LIMIT),
            websocket_inbound_limit: FixedWindowLimiter::new(
                limits.websocket_inbound_messages_per_minute(),
            ),
            websocket_connections: events::ConnectionRegistry::new(
                limits.websocket_connections_per_principal(),
            ),
            shutdown: shutdown.clone(),
        });
        let router = router(Arc::clone(&state));
        let listener = LimitedTcpListener::new(listener, config.max_connections);
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<PeerAddress>(),
            )
            .with_graceful_shutdown(async move {
                while !*receiver.borrow() {
                    if receiver.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
        });
        Ok(Self {
            local_addr,
            shutdown: Some(shutdown),
            task: Some(task),
            shutdown_grace: config.shutdown_grace,
            shutdown_service,
        })
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(mut self) -> Result<(), DaemonServerError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(true);
        }
        let mut task = self.task.take().expect("server task is present");
        match tokio::time::timeout(self.shutdown_grace, &mut task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => return Err(DaemonServerError::ServeFailed(error)),
            Ok(Err(error)) => return Err(DaemonServerError::TaskFailed(error)),
            Err(_) => {
                task.abort();
                let _ = task.await;
                return Err(DaemonServerError::ShutdownTimedOut);
            }
        }
        self.wait_for_workers().await
    }

    async fn wait_for_workers(&self) -> Result<(), DaemonServerError> {
        let deadline = tokio::time::Instant::now() + self.shutdown_grace;
        loop {
            let service = self.shutdown_service.clone();
            match tokio::task::spawn_blocking(move || service.daemon_workers_idle()).await {
                Ok(Ok(true)) => return Ok(()),
                Ok(Ok(false)) => {}
                Ok(Err(_)) | Err(_) => return Err(DaemonServerError::HostShutdownFailed),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(DaemonServerError::ShutdownTimedOut);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl fmt::Debug for DaemonServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonServer")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl Drop for DaemonServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(true);
        }
    }
}

#[derive(Debug)]
pub enum DaemonServerError {
    NonLoopbackPlaintextBind,
    InvalidConnectionLimit,
    InvalidShutdownGrace,
    HostInitializationFailed,
    BindFailed(std::io::Error),
    ServeFailed(std::io::Error),
    TaskFailed(tokio::task::JoinError),
    ShutdownTimedOut,
    HostShutdownFailed,
}

impl DaemonServerError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NonLoopbackPlaintextBind => "non-loopback-plaintext-bind",
            Self::InvalidConnectionLimit => "invalid-connection-limit",
            Self::InvalidShutdownGrace => "invalid-shutdown-grace",
            Self::HostInitializationFailed => "host-initialization-failed",
            Self::BindFailed(_) => "bind-failed",
            Self::ServeFailed(_) => "serve-failed",
            Self::TaskFailed(_) => "server-task-failed",
            Self::ShutdownTimedOut => "shutdown-timeout",
            Self::HostShutdownFailed => "host-shutdown-failed",
        }
    }
}

impl fmt::Display for DaemonServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonLoopbackPlaintextBind => {
                "plaintext Host Daemon transport must bind to a loopback address"
            }
            Self::InvalidConnectionLimit => "the Host Daemon connection limit must be positive",
            Self::InvalidShutdownGrace => "the Host Daemon shutdown grace period must be positive",
            Self::HostInitializationFailed => {
                "the Host Daemon could not initialize its authoritative state"
            }
            Self::BindFailed(_) => "the Host Daemon could not bind its listener",
            Self::ServeFailed(_) => "the Host Daemon listener failed",
            Self::TaskFailed(_) => "the Host Daemon server task failed",
            Self::ShutdownTimedOut => {
                "the Host Daemon exceeded its graceful HTTP shutdown deadline"
            }
            Self::HostShutdownFailed => "the Host Daemon could not finalize its execution workers",
        })
    }
}

impl std::error::Error for DaemonServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BindFailed(error) | Self::ServeFailed(error) => Some(error),
            Self::TaskFailed(error) => Some(error),
            _ => None,
        }
    }
}

pub(super) struct DaemonState {
    service: Arc<HostService>,
    host_identity: String,
    started_at: OffsetDateTime,
    capabilities: DaemonRuntimeCapabilities,
    limits: EffectiveLimits,
    failed_auth_limit: FailedAuthLimiter,
    authenticated_limit: FixedWindowLimiter<String>,
    control_limit: FixedWindowLimiter<String>,
    websocket_inbound_limit: FixedWindowLimiter<String>,
    websocket_connections: Arc<events::ConnectionRegistry>,
    shutdown: watch::Sender<bool>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PeerAddress(SocketAddr);

impl Connected<IncomingStream<'_, LimitedTcpListener>> for PeerAddress {
    fn connect_info(stream: IncomingStream<'_, LimitedTcpListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

fn router(state: Arc<DaemonState>) -> Router {
    let bodyless_read_routes = Router::new()
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/host/status", get(host_status))
        .route("/v1/host/desktop-sessions", get(host_desktop_sessions))
        .route("/v1/sessions/{session_id}", get(sessions::get_session))
        .route("/v1/events", get(events::get_events))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_empty_read,
        ));
    let logs_route = Router::new()
        .route("/v1/logs", get(logs::get_logs))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_query_read,
        ));
    let read_routes =
        bodyless_read_routes
            .merge(logs_route)
            .route_layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                auth::require_read,
            ));
    let control_routes = Router::new()
        .route("/v1/sessions", post(sessions::create_session))
        .route(
            "/v1/sessions/{session_id}/turns",
            post(sessions::create_turn),
        )
        .route(
            "/v1/sessions/{session_id}/stop",
            post(sessions::stop_session),
        )
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_control,
        ));
    let protected = read_routes
        .merge(control_routes)
        .method_not_allowed_fallback(protected_method_not_allowed)
        .fallback(protected_not_found)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::authorize,
        ));
    Router::new()
        .route("/v1/live", get(live).fallback(live_method_not_allowed))
        .merge(protected)
        .with_state(state)
}

async fn live(headers: HeaderMap) -> Response {
    json_response(
        StatusCode::OK,
        &LiveResponse::new(),
        request_id_or_new(&headers),
    )
}

async fn live_method_not_allowed(headers: HeaderMap) -> Response {
    api_error_response(
        request_id_or_new(&headers),
        None,
        ApiFailure {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: ApiErrorCode::MethodNotAllowed,
            category: ApiErrorCategory::InvalidRequest,
            retryable: false,
            message: "the requested method is not supported by the liveness route",
            details: None,
        },
    )
}

async fn capabilities(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
) -> Response {
    let response = CapabilitiesResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        env!("CARGO_PKG_VERSION").to_string(),
        state.capabilities.codex_runtime(),
        state.capabilities.native_computer_use(),
        state.capabilities.provider_computer_use(),
        state.limits,
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

async fn host_status(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
) -> Response {
    let service = Arc::clone(&state.service);
    let status = match tokio::task::spawn_blocking(move || service.daemon_runtime_status()).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) | Err(_) => {
            return api_error_response(
                authorized.request_id().clone(),
                Some(state.host_identity.clone()),
                ApiFailure {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    code: ApiErrorCode::InternalError,
                    category: ApiErrorCategory::Internal,
                    retryable: false,
                    message: "the Host Daemon could not read authoritative status",
                    details: None,
                },
            );
        }
    };
    let response = HostStatusResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        env!("CARGO_PKG_VERSION").to_string(),
        state.started_at,
        status.session_count(),
        status.active_turn_count(),
        status.recovery_pending_turn_count(),
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

async fn host_desktop_sessions(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
) -> Response {
    let service = Arc::clone(&state.service);
    let sessions =
        match tokio::task::spawn_blocking(move || service.daemon_desktop_sessions()).await {
            Ok(Ok(sessions)) => sessions,
            Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
            Err(_) => return host_error::task_failure(&state, &authorized),
        };
    let response = HostDesktopSessionsResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        sessions,
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

async fn protected_not_found(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: StatusCode::NOT_FOUND,
            code: ApiErrorCode::RouteNotFound,
            category: ApiErrorCategory::NotFound,
            retryable: false,
            message: "the requested Host Daemon route does not exist",
            details: None,
        },
    )
}

async fn protected_method_not_allowed(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: ApiErrorCode::MethodNotAllowed,
            category: ApiErrorCategory::InvalidRequest,
            retryable: false,
            message: "the requested method is not supported by this Host Daemon route",
            details: None,
        },
    )
}

pub(super) struct ApiFailure {
    pub(super) status: StatusCode,
    pub(super) code: ApiErrorCode,
    pub(super) category: ApiErrorCategory,
    pub(super) retryable: bool,
    pub(super) message: &'static str,
    pub(super) details: Option<Value>,
}

pub(super) fn api_error_response(
    request_id: RequestId,
    host_identity: Option<String>,
    failure: ApiFailure,
) -> Response {
    let fallback_request_id = request_id.clone();
    let fallback_host_identity = host_identity.clone();
    json_response_with_context(
        failure.status,
        &ApiError::new(
            request_id,
            host_identity,
            failure.code,
            failure.category,
            failure.retryable,
            failure.message,
            failure.details,
        ),
        fallback_request_id,
        fallback_host_identity,
    )
}

fn json_response(status: StatusCode, value: &impl Serialize, request_id: RequestId) -> Response {
    json_response_with_context(status, value, request_id, None)
}

pub(super) fn authenticated_json_response(
    status: StatusCode,
    value: &impl Serialize,
    request_id: &RequestId,
    host_identity: &str,
) -> Response {
    json_response_with_context(
        status,
        value,
        request_id.clone(),
        Some(host_identity.to_string()),
    )
}

fn json_response_with_context(
    status: StatusCode,
    value: &impl Serialize,
    request_id: RequestId,
    host_identity: Option<String>,
) -> Response {
    let response_host_identity = host_identity.clone();
    let (status, body) = match serde_json::to_vec(value) {
        Ok(body) => (status, body),
        Err(_) => {
            let fallback = ApiError::new(
                request_id.clone(),
                host_identity,
                ApiErrorCode::InternalError,
                ApiErrorCategory::Internal,
                false,
                "the Host Daemon could not encode its response",
                None,
            );
            let body = serde_json::to_vec(&fallback)
                .expect("the closed fallback ApiError contract must serialize");
            (StatusCode::INTERNAL_SERVER_ERROR, body)
        }
    };
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    security_headers(with_response_context(
        response,
        &request_id,
        response_host_identity.as_deref(),
    ))
}

pub(super) fn with_response_context(
    mut response: Response,
    request_id: &RequestId,
    host_identity: Option<&str>,
) -> Response {
    let response_request_id = HeaderValue::try_from(request_id.as_str())
        .expect("a canonical UUIDv7 is always a valid HTTP header value");
    tracing::debug!(
        request_id = %request_id,
        status = response.status().as_u16(),
        "Host Daemon HTTP response completed"
    );
    response
        .headers_mut()
        .insert(REQUEST_ID_HEADER, response_request_id);
    if let Some(host_identity) = host_identity {
        let response_host_identity = HeaderValue::try_from(host_identity)
            .expect("a stored Host Identity is always a valid HTTP header value");
        response
            .headers_mut()
            .insert(HOST_IDENTITY_HEADER, response_host_identity);
    }
    response
}

pub(super) fn security_headers(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

pub(super) fn header_request_id(headers: &HeaderMap) -> Option<RequestId> {
    let mut values = headers.get_all(REQUEST_ID_HEADER).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    RequestId::parse(value).ok()
}

pub(super) fn request_id_or_new(headers: &HeaderMap) -> RequestId {
    header_request_id(headers).unwrap_or_default()
}

struct RateWindow {
    started_at: Instant,
    count: usize,
}

impl RateWindow {
    fn is_active(&self, now: Instant) -> bool {
        now.duration_since(self.started_at) < RATE_WINDOW
    }

    fn retry_after(&self, now: Instant) -> Duration {
        RATE_WINDOW.saturating_sub(now.saturating_duration_since(self.started_at))
    }
}

struct FixedWindowLimiter<K> {
    limit: usize,
    entries: Mutex<HashMap<K, RateWindow>>,
}

impl<K> FixedWindowLimiter<K>
where
    K: Eq + Hash,
{
    fn new(limit: usize) -> Self {
        Self {
            limit,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `None` when the request is admitted and the remaining window
    /// when it is limited. Keeping the duration in the limiter prevents HTTP
    /// and WebSocket callers from reconstructing timing from policy constants.
    fn admit(&self, key: K) -> Option<Duration> {
        self.admit_at(key, Instant::now())
    }

    fn admit_at(&self, key: K, now: Instant) -> Option<Duration> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        entries.retain(|_, window| window.is_active(now));
        if !entries.contains_key(&key) && entries.len() >= MAX_RATE_KEYS {
            return entries.values().map(|window| window.retry_after(now)).min();
        }
        let window = entries.entry(key).or_insert(RateWindow {
            started_at: now,
            count: 0,
        });
        if window.count >= self.limit {
            Some(window.retry_after(now))
        } else {
            window.count += 1;
            None
        }
    }
}

struct FailedAuthLimiter {
    entries: Mutex<HashMap<IpAddr, RateWindow>>,
}

impl FailedAuthLimiter {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn retry_after(&self, source: IpAddr) -> Option<Duration> {
        self.retry_after_at(source, Instant::now())
    }

    fn retry_after_at(&self, source: IpAddr, now: Instant) -> Option<Duration> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        entries.retain(|_, window| window.is_active(now));
        entries
            .get(&source)
            .filter(|window| window.count >= FAILED_AUTH_LIMIT)
            .map(|window| window.retry_after(now))
    }

    fn record_failure(&self, source: IpAddr) {
        self.record_failure_at(source, Instant::now());
    }

    fn record_failure_at(&self, source: IpAddr, now: Instant) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        entries.retain(|_, window| window.is_active(now));
        if !entries.contains_key(&source) && entries.len() >= MAX_RATE_KEYS {
            return;
        }
        entries
            .entry(source)
            .and_modify(|window| window.count = window.count.saturating_add(1))
            .or_insert(RateWindow {
                started_at: now,
                count: 1,
            });
    }
}

fn retry_after_ms(duration: Duration) -> u64 {
    let rounded_millis =
        duration.as_millis() + u128::from(!duration.subsec_nanos().is_multiple_of(1_000_000));
    u64::try_from(rounded_millis).expect("the one-minute rate window fits in u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    struct SerializationFailure;

    impl Serialize for SerializationFailure {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("forced serialization failure"))
        }
    }

    #[tokio::test]
    async fn serialization_failure_still_returns_the_typed_error_contract() {
        let request_id = RequestId::new();
        let response = json_response_with_context(
            StatusCode::OK,
            &SerializationFailure,
            request_id.clone(),
            Some("host-test".to_string()),
        );
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 16_384)
            .await
            .expect("read typed fallback body");
        let error: ApiError = serde_json::from_slice(&body).expect("decode typed fallback");
        assert_eq!(error.code(), ApiErrorCode::InternalError);
        assert_eq!(error.request_id(), &request_id);
        assert_eq!(error.host_identity(), Some("host-test"));
    }

    #[test]
    fn fixed_window_reports_remaining_time_and_reopens_at_expiry() {
        let limiter = FixedWindowLimiter::new(1);
        let started_at = Instant::now();

        assert_eq!(limiter.admit_at("principal", started_at), None);
        assert_eq!(
            limiter.admit_at("principal", started_at + Duration::from_millis(125),),
            Some(RATE_WINDOW - Duration::from_millis(125))
        );
        assert_eq!(
            limiter.admit_at("principal", started_at + RATE_WINDOW),
            None
        );
    }

    #[test]
    fn failed_auth_window_reports_remaining_time_and_expires() {
        let limiter = FailedAuthLimiter::new();
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let started_at = Instant::now();
        for _ in 0..FAILED_AUTH_LIMIT {
            limiter.record_failure_at(source, started_at);
        }

        assert_eq!(
            limiter.retry_after_at(source, started_at + Duration::from_millis(250)),
            Some(RATE_WINDOW - Duration::from_millis(250))
        );
        assert_eq!(
            limiter.retry_after_at(source, started_at + RATE_WINDOW),
            None
        );
    }

    #[test]
    fn full_key_table_reports_the_earliest_window_expiry() {
        let limiter = FixedWindowLimiter::new(1);
        let started_at = Instant::now();
        for key in 0..MAX_RATE_KEYS {
            assert_eq!(limiter.admit_at(key, started_at), None);
        }

        assert_eq!(
            limiter.admit_at(MAX_RATE_KEYS, started_at + Duration::from_secs(1)),
            Some(RATE_WINDOW - Duration::from_secs(1))
        );
        assert_eq!(
            limiter.admit_at(MAX_RATE_KEYS, started_at + RATE_WINDOW),
            None
        );
    }

    #[test]
    fn retry_metadata_rounds_up_to_the_next_millisecond() {
        assert_eq!(retry_after_ms(Duration::from_nanos(1)), 1);
        assert_eq!(retry_after_ms(Duration::from_micros(1_001)), 2);
        assert_eq!(retry_after_ms(Duration::from_millis(60_000)), 60_000);
    }
}
