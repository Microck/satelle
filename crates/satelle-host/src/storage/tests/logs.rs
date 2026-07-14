use super::*;
use crate::{LogCursor, LogEvent, LogPageQuery, LogSeverity, LogSource};

fn host_log(at: OffsetDateTime, source: LogSource, severity: LogSeverity) -> SafeLogRecord {
    SafeLogRecord::new(
        at,
        source,
        severity,
        LogEvent::StoreOpened,
        crate::LogSubject::Host,
    )
    .expect("Host log record is valid")
}

#[test]
fn log_pages_filter_before_limiting_and_resume_after_the_delivered_cursor() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let now = OffsetDateTime::now_utc();
    let first = storage
        .append_safe_log(&host_log(now, LogSource::Storage, LogSeverity::Info))
        .expect("append first log");
    let second = storage
        .append_safe_log(&host_log(
            now + time::Duration::seconds(1),
            LogSource::HostDaemon,
            LogSeverity::Warning,
        ))
        .expect("append second log");
    let third = storage
        .append_safe_log(&host_log(
            now + time::Duration::seconds(2),
            LogSource::CodexAdapter,
            LogSeverity::Error,
        ))
        .expect("append third log");

    let tail = storage
        .log_page(&LogPageQuery::tail(2).expect("valid tail query"))
        .expect("read tail page");
    assert_eq!(
        tail.entries()
            .iter()
            .map(|entry| entry.cursor().position())
            .collect::<Vec<_>>(),
        vec![second, third]
    );
    assert!(tail.truncated());
    assert_eq!(tail.next_cursor().position(), third);

    let filtered = storage
        .log_page(
            &LogPageQuery::forward(Some(LogCursor::from_position(first)), 1)
                .expect("valid forward query")
                .with_sources([LogSource::CodexAdapter]),
        )
        .expect("read filtered forward page");
    assert_eq!(filtered.entries().len(), 1);
    assert_eq!(filtered.entries()[0].cursor().position(), third);
    assert!(!filtered.truncated());
    assert_eq!(filtered.next_cursor().position(), third);

    let future = storage
        .log_page(
            &LogPageQuery::forward(Some(LogCursor::from_position(third + 1)), 1)
                .expect("valid future-shaped query"),
        )
        .expect_err("a cursor above the store high-water mark must be rejected");
    assert!(matches!(future, LogPageStorageError::CursorAhead));
}

#[test]
fn log_pages_treat_future_since_values_as_an_empty_result() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let cursor = storage
        .append_safe_log(&host_log(
            OffsetDateTime::now_utc(),
            LogSource::Storage,
            LogSeverity::Info,
        ))
        .expect("append current log");
    let future =
        OffsetDateTime::parse("2999-01-01T00:00:00Z", &Rfc3339).expect("future RFC 3339 timestamp");

    let page = storage
        .log_page(
            &LogPageQuery::forward(None, 10)
                .expect("valid forward query")
                .with_since(future),
        )
        .expect("a future lower bound is a valid empty query");

    assert!(page.entries().is_empty());
    assert!(!page.truncated());
    assert_eq!(page.next_cursor().position(), cursor);
}

#[test]
fn retention_expires_only_cursors_that_can_no_longer_resume_the_retained_prefix() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let now = OffsetDateTime::now_utc();
    let expired = storage
        .append_safe_log(&host_log(
            now - time::Duration::days(8),
            LogSource::Storage,
            LogSeverity::Info,
        ))
        .expect("append expiring log");
    let retained = storage
        .append_safe_log(&host_log(now, LogSource::Storage, LogSeverity::Info))
        .expect("append retained log");

    let expired_error = storage
        .log_page(
            &LogPageQuery::forward(Some(LogCursor::from_position(0)), 10)
                .expect("valid expired query"),
        )
        .expect_err("origin cursor must expire after retained history advances");
    assert_eq!(expired_error.earliest_available_cursor(), Some(retained));
    assert_eq!(expired_error.resume_cursor(), Some(expired));

    let resumed = storage
        .log_page(
            &LogPageQuery::forward(Some(LogCursor::from_position(expired)), 10)
                .expect("valid boundary query"),
        )
        .expect("the last expired cursor remains a valid resume boundary");
    assert_eq!(resumed.entries()[0].cursor().position(), retained);
}

#[test]
fn logs_expire_only_after_the_exact_seven_day_boundary() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let recorded_at = at(0);
    let expired_cursor = storage
        .append_safe_log(&host_log(
            recorded_at - time::Duration::nanoseconds(1),
            LogSource::Storage,
            LogSeverity::Info,
        ))
        .expect("append log that forces exact-boundary pruning");
    let boundary_cursor = storage
        .append_safe_log(&host_log(
            recorded_at,
            LogSource::Storage,
            LogSeverity::Info,
        ))
        .expect("append retained log");

    storage
        .prune_expired_session_metadata(recorded_at + time::Duration::days(7))
        .expect("maintain retention at the exact boundary");
    assert_eq!(
        storage
            .logs_after(None, 10)
            .expect("read log at the exact retention boundary")
            .into_iter()
            .map(|record| record.cursor())
            .collect::<Vec<_>>(),
        vec![boundary_cursor],
        "actual pruning must delete the older row but retain the exact-boundary row"
    );
    assert!(boundary_cursor > expired_cursor);

    storage
        .prune_expired_session_metadata(
            recorded_at + time::Duration::days(7) + time::Duration::nanoseconds(1),
        )
        .expect("maintain retention after the exact boundary");
    assert!(
        storage
            .logs_after(None, 10)
            .expect("read logs after retention expiry")
            .is_empty()
    );
}

#[test]
fn log_cursors_continue_increasing_after_full_pruning_and_reopen() {
    let state = TempDir::new().expect("temporary state directory");
    let recorded_at = at(0);
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let deleted_cursor = storage
        .append_safe_log(&host_log(
            recorded_at,
            LogSource::Storage,
            LogSeverity::Info,
        ))
        .expect("append log that will expire");
    storage
        .prune_expired_session_metadata(
            recorded_at + time::Duration::days(7) + time::Duration::nanoseconds(1),
        )
        .expect("prune the complete log history");
    assert!(
        storage
            .logs_after(None, 10)
            .expect("confirm the complete log history was pruned")
            .is_empty()
    );

    drop(storage);

    let (mut reopened, _) = Storage::open(state.path()).expect("reopen the fully pruned store");
    assert!(
        reopened
            .logs_after(None, 10)
            .expect("confirm the reopened log table remains empty")
            .is_empty()
    );
    let after_reopen = reopened
        .append_safe_log(&host_log(
            recorded_at + time::Duration::days(8),
            LogSource::Storage,
            LogSeverity::Info,
        ))
        .expect("append the first log after reopening the fully pruned store");
    assert!(after_reopen > deleted_cursor);

    let following_cursor = reopened
        .append_safe_log(&host_log(
            recorded_at + time::Duration::days(8) + time::Duration::seconds(1),
            LogSource::Storage,
            LogSeverity::Info,
        ))
        .expect("append the following retained log");
    assert!(following_cursor > after_reopen);
    assert_eq!(
        reopened
            .logs_after(None, 10)
            .expect("read retained logs in cursor order")
            .into_iter()
            .map(|record| record.cursor())
            .collect::<Vec<_>>(),
        vec![after_reopen, following_cursor]
    );
}

#[test]
fn appended_log_timestamps_cannot_move_backwards_behind_the_cursor_order() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let now = OffsetDateTime::now_utc();
    let first = storage
        .append_safe_log(&host_log(now, LogSource::Storage, LogSeverity::Info))
        .expect("append current log");
    let second = storage
        .append_safe_log(&host_log(
            now - time::Duration::days(8),
            LogSource::Storage,
            LogSeverity::Warning,
        ))
        .expect("append log after a backward clock observation");

    let stored = storage
        .logs_after(None, 10)
        .expect("read logs in cursor order");
    assert_eq!(
        stored
            .iter()
            .map(StoredLogRecord::cursor)
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    assert_eq!(stored[0].record().recorded_at(), now);
    assert_eq!(stored[1].record().recorded_at(), now);

    let page = storage
        .log_page(&LogPageQuery::tail(10).expect("valid tail query"))
        .expect("read page after retention maintenance");
    assert_eq!(page.entries().len(), 2);
}

#[test]
fn persisted_log_rows_with_partial_subjects_are_rejected() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");
    let now = OffsetDateTime::now_utc();
    let recorded_at = now.format(&Rfc3339).expect("format fixture time");
    let recorded_at_unix_nanos =
        i64::try_from(now.unix_timestamp_nanos()).expect("fixture time fits SQLite");
    let insert_partial_subject = "INSERT INTO logs (recorded_at, recorded_at_unix_nanos, source, severity, event_kind, session_state_revision) VALUES (?1, ?2, 'storage', 'warning', 'turn_state_committed', '0000000000000001')";
    storage
        .connection_for_test()
        .execute(
            insert_partial_subject,
            params![recorded_at, recorded_at_unix_nanos],
        )
        .expect_err("the SQLite schema must reject a partial Log Subject");

    // Bypass the schema only to prove the row decoder still fails closed if
    // database corruption presents an impossible subject shape.
    storage
        .connection_for_test()
        .pragma_update(None, "ignore_check_constraints", true)
        .expect("allow a deliberately corrupted fixture row");
    storage
        .connection_for_test()
        .execute(
            insert_partial_subject,
            params![recorded_at, recorded_at_unix_nanos],
        )
        .expect("insert structurally incomplete fixture row");
    storage
        .connection_for_test()
        .pragma_update(None, "ignore_check_constraints", false)
        .expect("restore check constraints");

    let error = storage
        .logs_after(None, 10)
        .expect_err("partial Log Subjects must not enter the domain model");
    assert_eq!(StorageErrorKind::InvalidStoredState, error.kind());
}

#[test]
fn log_reads_enforce_retention_even_when_no_new_log_has_been_written() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let expired = storage
        .append_safe_log(&host_log(
            OffsetDateTime::now_utc() - time::Duration::days(8),
            LogSource::Storage,
            LogSeverity::Info,
        ))
        .expect("append an old log");

    let page = storage
        .log_page(&LogPageQuery::tail(10).expect("valid tail query"))
        .expect("read after idle retention window");
    assert!(page.entries().is_empty());
    assert_eq!(page.next_cursor().position(), expired);

    let error = storage
        .log_page(
            &LogPageQuery::forward(Some(LogCursor::from_position(0)), 10)
                .expect("valid origin query"),
        )
        .expect_err("the pre-retention origin must be expired");
    assert_eq!(error.earliest_available_cursor(), None);
    assert_eq!(error.resume_cursor(), Some(expired));
}
