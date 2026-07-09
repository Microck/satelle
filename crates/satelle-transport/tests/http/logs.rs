use super::*;
use satelle_host::{LogCursor, LogPageQuery, LogSeverity, LogSource};
use satelle_transport::TurnRequest;

const LOG_CREATE_KEY: &str = "01890a5d-ac96-7b7c-8f89-37c3d0a66f31";

#[tokio::test]
async fn logs_route_pages_redacted_host_owned_entries_and_client_resumes() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let prompt = "PRIVATE_LOG_ROUTE_PROMPT_CANARY";
    let created = running
        .mutation("/v1/sessions", LOG_CREATE_KEY)
        .json(&TurnRequest::new(prompt))
        .send()
        .await
        .expect("create log-producing Session");
    assert_eq!(created.status(), StatusCode::ACCEPTED);
    wait_for_daemon_workers(&running).await;

    let response = running
        .request("/v1/logs?mode=tail&limit=10&minimum_severity=info")
        .send()
        .await
        .expect("read initial log tail");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.bytes().await.expect("read log page body");
    assert!(!String::from_utf8_lossy(&bytes).contains(prompt));
    let page: LogsPageResponse = serde_json::from_slice(&bytes).expect("decode log page");
    assert_eq!(page.host_identity(), running.host_identity);
    assert!(!page.page().entries().is_empty());
    assert!(page.page().entries().iter().all(|entry| {
        matches!(
            entry.source(),
            LogSource::HostDaemon | LogSource::Storage | LogSource::CodexAdapter
        )
    }));

    let address = running.server.local_addr();
    let host_identity = running.host_identity.clone();
    let token = {
        let exposed = running.token.expose();
        ApiBearerToken::parse(exposed.as_str()).expect("copy token into logs client")
    };
    let cursor = page.page().next_cursor();
    let appended = running
        .service
        .append_daemon_log_for_tests(
            time::OffsetDateTime::now_utc(),
            LogSource::Storage,
            LogSeverity::Info,
        )
        .expect("append a post-page log");
    let resumed = tokio::task::spawn_blocking(move || {
        let client = DaemonClient::loopback(address, token, host_identity)?;
        client.logs(
            &LogPageQuery::forward(Some(cursor), 10)
                .expect("valid forward query")
                .with_sources([LogSource::HostDaemon])
                .with_minimum_severity(LogSeverity::Info),
        )
    })
    .await
    .expect("join logs client request")
    .expect("resume logs through DaemonClient");
    assert_eq!(resumed.page().next_cursor(), appended);
    assert!(resumed.page().entries().is_empty());

    let storage_page: LogsPageResponse = running
        .request(&format!(
            "/v1/logs?mode=forward&cursor={cursor}&limit=10&sources=storage"
        ))
        .send()
        .await
        .expect("read matching forward logs")
        .json()
        .await
        .expect("decode matching forward page");
    assert_eq!(storage_page.page().entries().len(), 1);
    assert_eq!(storage_page.page().entries()[0].cursor(), appended);
}

#[tokio::test]
async fn logs_route_reports_cursor_expiry_and_the_earliest_retained_cursor() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let now = time::OffsetDateTime::now_utc();
    let expired = running
        .service
        .append_daemon_log_for_tests(
            now - time::Duration::days(8),
            LogSource::Storage,
            LogSeverity::Info,
        )
        .expect("append expiring log");
    let retained = running
        .service
        .append_daemon_log_for_tests(now, LogSource::Storage, LogSeverity::Info)
        .expect("append retained log");

    let response = running
        .request("/v1/logs?mode=forward&cursor=slc1_0000000000000000&limit=10")
        .send()
        .await
        .expect("request an expired cursor");
    assert_eq!(response.status(), StatusCode::GONE);
    let error: ApiError = response.json().await.expect("decode cursor expiry");
    assert_eq!(error.code().as_str(), "logs-cursor-expired");
    let retained_token = retained.to_string();
    let resume_token = expired.to_string();
    assert_eq!(
        error.details().and_then(|details| details
            .get("earliest_available_cursor")
            .and_then(Value::as_str)),
        Some(retained_token.as_str())
    );
    assert_eq!(
        error
            .details()
            .and_then(|details| details.get("resume_cursor").and_then(Value::as_str)),
        Some(resume_token.as_str())
    );

    let boundary: LogsPageResponse = running
        .request(&format!(
            "/v1/logs?mode=forward&cursor={resume_token}&limit=10"
        ))
        .send()
        .await
        .expect("resume after the last expired cursor")
        .json()
        .await
        .expect("decode retained boundary page");
    assert_eq!(boundary.page().entries()[0].cursor(), retained);
}

#[tokio::test]
async fn logs_route_rejects_every_invalid_query_shape_before_reading() {
    let running = RunningServer::start(ApiScopes::READ).await;
    for query in [
        "mode=tail&cursor=slc1_0000000000000000",
        "mode=forward&cursor=slc1_0000000000000001",
        "limit=0",
        "limit=10001",
        "sources=host_daemon,host_daemon",
        "sources=unknown",
        "minimum_severity=debug",
        "since=not-a-time",
        "session_id=not-a-session",
        "unknown=true",
        "limit=1&limit=2",
    ] {
        let response = running
            .request(&format!("/v1/logs?{query}"))
            .send()
            .await
            .unwrap_or_else(|error| panic!("send invalid log query {query}: {error}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query={query}");
        let error: ApiError = response.json().await.expect("decode log query error");
        assert_eq!(error.code().as_str(), "invalid-request", "query={query}");
    }

    for request in [
        running.request("/v1/logs").header("Cookie", "mode=tail"),
        running.request("/v1/logs").body("unexpected"),
    ] {
        let response = request.send().await.expect("send invalid log read shape");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[test]
fn opaque_log_cursor_is_not_a_raw_integer_contract() {
    assert!(LogCursor::parse("1").is_err());
    assert!(LogCursor::parse("slc1_0000000000000001").is_ok());
}

async fn wait_for_daemon_workers(running: &RunningServer) {
    for _ in 0..100 {
        if running
            .service
            .daemon_workers_idle()
            .expect("inspect daemon worker state")
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("daemon workers did not become idle within the test deadline")
}
