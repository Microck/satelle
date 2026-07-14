use super::{SatelleMcp, service_result, stdio};
use rmcp::service::QuitReason;
use std::future::{pending, ready};
use std::time::Duration;

#[tokio::test]
async fn local_state_gate_prefers_cancellation_and_releases_the_waiter() {
    let server = SatelleMcp::new(None);
    let held = server.local_state_gate.lock().await;

    let error = server
        .local_state_guard(true, ready(()))
        .await
        .expect_err("a cancelled local read must not remain queued");
    assert_eq!(error.message, "MCP tool request was cancelled");

    drop(held);
    let guard = tokio::time::timeout(
        Duration::from_millis(100),
        server.local_state_guard(true, pending()),
    )
    .await
    .expect("a cancelled waiter must not retain the local state gate")
    .expect("the next local read should acquire the gate");
    assert!(guard.is_some());
}

#[tokio::test]
async fn non_local_operation_bypasses_the_local_state_gate() {
    let server = SatelleMcp::new(None);
    let _held = server.local_state_gate.lock().await;

    let guard = tokio::time::timeout(
        Duration::from_millis(100),
        server.local_state_guard(false, pending()),
    )
    .await
    .expect("a non-local operation must not wait for local state")
    .expect("a non-local operation should not fail");
    assert!(guard.is_none());
}

#[tokio::test]
async fn stopping_the_framer_cancels_a_pending_input_task() {
    let framer = tokio::spawn(pending());
    stdio::stop_framer(framer)
        .await
        .expect("pending stdin framing should stop cleanly");
}

#[tokio::test]
async fn stopping_the_framer_preserves_a_completed_error() {
    let framer = tokio::spawn(async { Err(stdio::FramingError::Oversized) });
    while !framer.is_finished() {
        tokio::task::yield_now().await;
    }
    let error = stdio::stop_framer(framer)
        .await
        .expect_err("a completed framing error must survive shutdown");
    assert!(matches!(error, stdio::FramingError::Oversized));
}

#[tokio::test]
async fn service_termination_reports_cancellation_and_join_failures() {
    assert!(service_result(Ok(QuitReason::Closed)).is_ok());
    assert!(
        service_result(Ok(QuitReason::Cancelled))
            .expect_err("unexpected service cancellation must fail")
            .contains("cancelled")
    );

    let inner = tokio::spawn(pending::<()>());
    inner.abort();
    let inner_error = inner.await.expect_err("aborted inner task must fail");
    assert!(
        service_result(Ok(QuitReason::JoinError(inner_error)))
            .expect_err("nested request task failure must fail the service")
            .contains("request task failed")
    );

    let outer = tokio::spawn(pending::<()>());
    outer.abort();
    let outer_error = outer.await.expect_err("aborted service task must fail");
    assert!(
        service_result(Err(outer_error))
            .expect_err("service join failure must fail the process")
            .contains("server task failed")
    );
}
