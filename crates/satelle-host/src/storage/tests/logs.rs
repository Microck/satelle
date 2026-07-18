use super::*;
use crate::DaemonLogEntry;
use crate::{LogCursor, LogEvent, LogPageQuery, LogSeverity, LogSource};
use std::fs;
use std::path::Path;

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

fn committed_host_log(
    storage: &mut Storage,
    at: OffsetDateTime,
    source: LogSource,
    severity: LogSeverity,
) -> DaemonLogEntry {
    let cursor = storage
        .append_safe_log(&host_log(at, source, severity))
        .expect("commit authoritative SQLite log");
    storage
        .committed_log_entry(cursor)
        .expect("load authoritative committed Log Entry")
}

fn operator_log_cursors(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .expect("read operator log generation")
        .lines()
        .map(|line| {
            line.split_ascii_whitespace()
                .find_map(|field| field.strip_prefix("cursor="))
                .expect("operator log line has a cursor")
                .to_string()
        })
        .collect()
}

fn cursor_strings(positions: &[u64]) -> Vec<String> {
    positions
        .iter()
        .map(|position| LogCursor::from_position(*position).to_string())
        .collect()
}

fn assert_sqlite_log_cursors(storage: &Storage, expected: &[u64]) {
    assert_eq!(
        storage
            .logs_after(None, 10)
            .expect("read authoritative SQLite logs")
            .into_iter()
            .map(|record| record.cursor())
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn operator_log_formats_the_authoritative_normalized_entry_only() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let log_root = state.path().join("operator-logs");
    let mut operator_log = OperatorLogSink::new(OperatorLogPolicy::new(log_root.clone()));

    let authoritative_timestamp = at(1);
    let _first = committed_host_log(
        &mut storage,
        authoritative_timestamp,
        LogSource::Storage,
        LogSeverity::Info,
    );
    let normalized = committed_host_log(
        &mut storage,
        at(0),
        LogSource::Storage,
        LogSeverity::Warning,
    );
    assert_eq!(normalized.timestamp(), authoritative_timestamp);

    let outcome = operator_log.write_committed(&normalized);

    assert!(matches!(outcome, OperatorLogWriteOutcome::Written));
    assert_eq!(
        fs::read_to_string(log_root.join("satelle-host.log")).expect("read operator log fixture"),
        concat!(
            "2026-01-02T03:04:01Z level=warn source=storage ",
            "event=store_opened subject=host cursor=slc1_0000000000000002 ",
            "message=\"opened Host state store\"\n",
        )
    );
}

#[test]
fn operator_log_rotates_only_above_the_threshold_and_retains_newest_generations() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let log_root = state.path().join("operator-logs");
    let policy = OperatorLogPolicy::new(log_root.clone());
    assert_eq!(policy.rotation_bytes_for_test(), 10 * 1024 * 1024);
    assert_eq!(policy.retained_files_for_test(), 5);

    let first = committed_host_log(
        &mut storage,
        at(0),
        LogSource::HostDaemon,
        LogSeverity::Warning,
    );
    let probe_root = state.path().join("operator-log-probe");
    let mut probe = OperatorLogSink::new(OperatorLogPolicy::new(probe_root.clone()));
    assert!(matches!(
        probe.write_committed(&first),
        OperatorLogWriteOutcome::Written
    ));
    let line_bytes = fs::metadata(probe_root.join("satelle-host.log"))
        .expect("probe operator log metadata")
        .len();
    let threshold = line_bytes * 2;

    let mut operator_log =
        OperatorLogSink::new(OperatorLogPolicy::for_test(log_root.clone(), threshold, 5));
    assert!(matches!(
        operator_log.write_committed(&first),
        OperatorLogWriteOutcome::Written
    ));
    let second = committed_host_log(
        &mut storage,
        at(0),
        LogSource::HostDaemon,
        LogSeverity::Warning,
    );
    assert!(matches!(
        operator_log.write_committed(&second),
        OperatorLogWriteOutcome::Written
    ));
    assert_eq!(
        fs::metadata(log_root.join("satelle-host.log"))
            .expect("current operator log metadata at threshold")
            .len(),
        threshold
    );
    assert!(!log_root.join("satelle-host.log.1").exists());

    let third = committed_host_log(
        &mut storage,
        at(0),
        LogSource::HostDaemon,
        LogSeverity::Warning,
    );
    assert!(matches!(
        operator_log.write_committed(&third),
        OperatorLogWriteOutcome::Written
    ));
    assert_eq!(
        operator_log_cursors(&log_root.join("satelle-host.log")),
        cursor_strings(&[3])
    );
    assert_eq!(
        operator_log_cursors(&log_root.join("satelle-host.log.1")),
        cursor_strings(&[1, 2])
    );

    for _ in 4..=11 {
        let entry = committed_host_log(
            &mut storage,
            at(0),
            LogSource::HostDaemon,
            LogSeverity::Warning,
        );
        assert!(matches!(
            operator_log.write_committed(&entry),
            OperatorLogWriteOutcome::Written
        ));
    }

    assert_eq!(
        operator_log_cursors(&log_root.join("satelle-host.log")),
        cursor_strings(&[11])
    );
    assert_eq!(
        operator_log_cursors(&log_root.join("satelle-host.log.1")),
        cursor_strings(&[9, 10])
    );
    assert_eq!(
        operator_log_cursors(&log_root.join("satelle-host.log.2")),
        cursor_strings(&[7, 8])
    );
    assert_eq!(
        operator_log_cursors(&log_root.join("satelle-host.log.3")),
        cursor_strings(&[5, 6])
    );
    assert_eq!(
        operator_log_cursors(&log_root.join("satelle-host.log.4")),
        cursor_strings(&[3, 4])
    );
    assert!(!log_root.join("satelle-host.log.5").exists());
}

#[cfg(unix)]
#[test]
fn operator_log_directory_and_rotated_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let log_root = state.path().join("operator-logs");
    let mut operator_log =
        OperatorLogSink::new(OperatorLogPolicy::for_test(log_root.clone(), 1, 5));
    for second in 1..=3 {
        let entry = committed_host_log(
            &mut storage,
            at(second),
            LogSource::Storage,
            LogSeverity::Info,
        );
        assert!(matches!(
            operator_log.write_committed(&entry),
            OperatorLogWriteOutcome::Written
        ));
    }

    assert_eq!(
        fs::metadata(&log_root)
            .expect("operator log root metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for entry in fs::read_dir(&log_root).expect("read operator log root") {
        assert_eq!(
            entry
                .expect("read operator log directory entry")
                .metadata()
                .expect("operator log file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn operator_log_failures_are_coalesced_and_do_not_roll_back_sqlite() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let unusable_log_root = state.path().join("not-a-directory");
    fs::write(&unusable_log_root, b"occupied").expect("create unusable log root fixture");
    let mut operator_log = OperatorLogSink::new(OperatorLogPolicy::new(unusable_log_root.clone()));

    let first = committed_host_log(&mut storage, at(0), LogSource::Storage, LogSeverity::Info);
    let first_outcome = operator_log.write_committed(&first);
    assert_eq!(
        first_outcome.failure_kind(),
        Some(OperatorLogFailureKind::BoundaryUnavailable)
    );
    assert_sqlite_log_cursors(&storage, &[1]);

    let second = committed_host_log(
        &mut storage,
        at(1),
        LogSource::Storage,
        LogSeverity::Warning,
    );
    let second_outcome = operator_log.write_committed(&second);
    assert!(matches!(
        second_outcome,
        OperatorLogWriteOutcome::FailureCoalesced
    ));
    assert_sqlite_log_cursors(&storage, &[1, 2]);

    fs::remove_file(&unusable_log_root).expect("repair operator log boundary");
    let third = committed_host_log(&mut storage, at(2), LogSource::Storage, LogSeverity::Info);
    assert!(matches!(
        operator_log.write_committed(&third),
        OperatorLogWriteOutcome::Written
    ));
    assert_sqlite_log_cursors(&storage, &[1, 2, 3]);
    assert_eq!(
        operator_log_cursors(&unusable_log_root.join("satelle-host.log")),
        cursor_strings(&[3])
    );

    operator_log.release_handles_for_test();
    fs::remove_file(unusable_log_root.join("satelle-host.log"))
        .expect("remove repaired operator log file");
    fs::remove_dir(&unusable_log_root).expect("remove repaired operator log root");
    fs::write(&unusable_log_root, b"occupied again").expect("break operator log boundary again");
    let fourth = committed_host_log(&mut storage, at(3), LogSource::Storage, LogSeverity::Error);
    let fourth_outcome = operator_log.write_committed(&fourth);
    assert_eq!(
        fourth_outcome.failure_kind(),
        Some(OperatorLogFailureKind::BoundaryUnavailable)
    );
    assert_sqlite_log_cursors(&storage, &[1, 2, 3, 4]);
    assert!(unusable_log_root.is_file());
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
