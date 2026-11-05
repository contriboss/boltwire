//! Cancelling a query (dropping its future) must never leave a connection
//! that later hands one query's replies to another. Runs against a scripted
//! fake server; no database needed.

#[path = "support/fake_bolt.rs"]
mod fake_bolt;

use std::collections::HashMap;
use std::time::Duration;

use boltwire::{BoltConnection, BoltValue, Pool, QueryResult};
use fake_bolt::{FakeBolt, Options};

const CANCEL_AFTER: Duration = Duration::from_millis(50);

async fn connect(server: &FakeBolt) -> BoltConnection {
    BoltConnection::connect(server.addr(), None)
        .await
        .expect("connect to fake server")
}

fn pool(server: &FakeBolt, size: usize) -> Pool {
    let addr = server.addr();
    Pool::new(size, move || {
        let addr = addr.clone();
        async move { BoltConnection::connect(addr, None).await }
    })
}

fn assert_own_result(result: &QueryResult, query: &str) {
    assert_eq!(result.columns, vec!["q".to_string()], "columns of {query}");
    assert_eq!(
        result.records,
        vec![vec![BoltValue::from(query.to_string())]],
        "records of {query}"
    );
}

/// Drop `conn.run(query)` after `CANCEL_AFTER`; it must still be pending.
async fn cancel_run(conn: &mut BoltConnection, query: &str) {
    let cancelled = tokio::time::timeout(CANCEL_AFTER, conn.run(query, HashMap::new())).await;
    assert!(cancelled.is_err(), "{query} should still be in flight");
}

#[tokio::test]
async fn cancelled_run_does_not_leak_replies_into_the_next_query() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;

    cancel_run(&mut conn, "slow:200:first").await;
    // Let the late RUN reply land on the socket.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let result = conn
        .run("second", HashMap::new())
        .await
        .expect("connection recovers");
    assert_own_result(&result, "second");
    let result = conn
        .run("third", HashMap::new())
        .await
        .expect("still in sync");
    assert_own_result(&result, "third");
}

#[tokio::test]
async fn cancelled_run_is_recovered_by_an_explicit_reset() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;

    cancel_run(&mut conn, "slow:200:first").await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    // The late RUN SUCCESS must not be taken for RESET's reply.
    conn.reset().await.expect("reset");
    let result = conn
        .run("second", HashMap::new())
        .await
        .expect("in sync after reset");
    assert_own_result(&result, "second");
}

#[tokio::test]
async fn cancellation_mid_message_keeps_the_framing() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;

    // The RECORD arrives in two halves 200ms apart; cancel in between.
    let cancelled = tokio::time::timeout(
        Duration::from_millis(100),
        conn.run("split:200:first", HashMap::new()),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "the split record should still be pending"
    );
    tokio::time::sleep(Duration::from_millis(250)).await;

    let result = conn
        .run("second", HashMap::new())
        .await
        .expect("half-read message does not desync the stream");
    assert_own_result(&result, "second");
}

#[tokio::test]
async fn pooled_connection_cancelled_mid_query_is_not_reused_broken() {
    let server = FakeBolt::start().await;
    let pool = pool(&server, 1);

    {
        let mut conn = pool.get().await.expect("checkout");
        cancel_run(&mut conn, "slow:200:first").await;
    }
    tokio::time::sleep(Duration::from_millis(250)).await;

    let mut conn = pool.get().await.expect("checkout after cancel");
    let result = conn
        .run("second", HashMap::new())
        .await
        .expect("pool hands out a usable connection");
    assert_own_result(&result, "second");
}

#[tokio::test]
async fn cancellation_mid_write_does_not_reach_the_server_as_garbage() {
    // The server stops reading after LOGON, so a large RUN blocks mid-frame.
    let server = FakeBolt::start_with(Options {
        pause_after_logon: Some(Duration::from_millis(300)),
        ..Options::default()
    })
    .await;
    let pool = pool(&server, 1);

    {
        let mut conn = pool.get().await.expect("checkout");
        let huge = "x".repeat(32 * 1024 * 1024);
        let params = HashMap::from([("blob".to_string(), BoltValue::from(huge))]);
        let cancelled = tokio::time::timeout(CANCEL_AFTER, conn.run("first", params)).await;
        assert!(cancelled.is_err(), "the write should still be blocked");
    }

    // Whatever the pool hands out next must answer promptly and correctly,
    // not wait out a read timeout on a connection with half a frame sent.
    let mut conn = tokio::time::timeout(Duration::from_secs(5), pool.get())
        .await
        .expect("checkout is prompt")
        .expect("checkout");
    let result = tokio::time::timeout(Duration::from_secs(5), conn.run("second", HashMap::new()))
        .await
        .expect("query is prompt")
        .expect("query succeeds");
    assert_own_result(&result, "second");
}

#[tokio::test]
async fn cut_off_write_marks_the_connection_broken() {
    let server = FakeBolt::start_with(Options {
        pause_after_logon: Some(Duration::from_millis(300)),
        ..Options::default()
    })
    .await;
    let mut conn = connect(&server).await;
    assert!(conn.is_ready());

    let huge = "x".repeat(32 * 1024 * 1024);
    let params = HashMap::from([("blob".to_string(), BoltValue::from(huge))]);
    let cancelled = tokio::time::timeout(CANCEL_AFTER, conn.run("first", params)).await;
    assert!(cancelled.is_err(), "the write should still be blocked");

    assert!(conn.is_broken());
    assert!(!conn.is_ready());
    let err = conn
        .run("second", HashMap::new())
        .await
        .expect_err("a half-sent frame cannot be repaired");
    assert!(matches!(err, boltwire::BoltError::Closed(_)), "{err:?}");
}

#[tokio::test]
async fn cancelled_read_leaves_the_connection_recoverable_not_broken() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;

    cancel_run(&mut conn, "slow:200:first").await;
    assert!(!conn.is_broken(), "nothing was cut mid-frame");
    assert!(!conn.is_ready(), "a reply is still owed");

    let result = conn.run("second", HashMap::new()).await.expect("recovers");
    assert_own_result(&result, "second");
    assert!(conn.is_ready());
}

#[tokio::test]
async fn pool_closes_cancelled_connections_and_reuses_clean_ones() {
    let server = FakeBolt::start().await;
    let pool = pool(&server, 1);

    for query in ["a", "b"] {
        let mut conn = pool.get().await.expect("checkout");
        let result = conn.run(query, HashMap::new()).await.expect("query");
        assert_own_result(&result, query);
    }
    assert_eq!(server.accepted(), 1, "clean connections are reused");

    {
        let mut conn = pool.get().await.expect("checkout");
        cancel_run(&mut conn, "slow:200:c").await;
    }
    tokio::time::timeout(Duration::from_secs(5), server.wait_closed(1))
        .await
        .expect("the cancelled connection is closed, not pooled");

    let mut conn = pool.get().await.expect("checkout");
    let result = conn.run("d", HashMap::new()).await.expect("query");
    assert_own_result(&result, "d");
    assert_eq!(server.accepted(), 2);
}

#[tokio::test]
async fn abandoned_transaction_is_reset_and_reused_by_the_pool() {
    let server = FakeBolt::start().await;
    let pool = pool(&server, 1);

    {
        let mut conn = pool.get().await.expect("checkout");
        let mut tx = conn.begin().await.expect("begin");
        tx.run("in-tx", HashMap::new()).await.expect("run");
        // dropped without commit or rollback
    }

    let mut conn = pool.get().await.expect("checkout");
    let result = conn.run("after", HashMap::new()).await.expect("query");
    assert_own_result(&result, "after");
    assert_eq!(
        server.accepted(),
        1,
        "no reply was owed, so RESET recovers it"
    );
    assert_eq!(
        server.signatures(0).last(),
        Some(&boltwire::message::PULL),
        "sanity: the last request was the query's PULL"
    );
    assert!(server.signatures(0).contains(&boltwire::message::RESET));
}

#[tokio::test]
async fn failed_begin_leaves_the_session_recoverable() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;

    // BEGIN's FAILURE puts the server session in FAILED; the next query must
    // RESET first rather than have its RUN IGNORED.
    let opts = boltwire::TxOptions {
        db: Some("fail".into()),
        ..boltwire::TxOptions::default()
    };
    let err = conn.begin_with(opts).await.err().expect("scripted failure");
    assert!(
        matches!(err, boltwire::BoltError::Failure { .. }),
        "{err:?}"
    );
    assert!(!conn.is_ready());

    let result = conn.run("after", HashMap::new()).await.expect("query");
    assert_own_result(&result, "after");
}

#[tokio::test]
async fn failed_query_leaves_the_session_ready() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;

    let err = conn
        .run("fail:x", HashMap::new())
        .await
        .expect_err("scripted failure");
    assert!(
        matches!(err, boltwire::BoltError::Failure { .. }),
        "{err:?}"
    );
    assert!(conn.is_ready(), "fail_reset recovered the session");

    let result = conn.run("after", HashMap::new()).await.expect("query");
    assert_own_result(&result, "after");
}

#[tokio::test]
async fn cancelled_statement_aborts_its_transaction() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;

    {
        let mut tx = conn.begin().await.expect("begin");
        let cancelled =
            tokio::time::timeout(CANCEL_AFTER, tx.run("slow:200:in-tx", HashMap::new())).await;
        assert!(cancelled.is_err(), "statement still in flight");

        let err = tx
            .run("next", HashMap::new())
            .await
            .expect_err("the transaction cannot go on");
        assert!(
            matches!(&err, boltwire::BoltError::Protocol(m) if m.contains("did not finish")),
            "{err:?}"
        );
        assert!(tx.commit().await.is_err(), "nor commit");
    }

    let result = conn.run("after", HashMap::new()).await.expect("recovers");
    assert_own_result(&result, "after");
}
