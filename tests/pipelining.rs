//! RUN and its first PULL go out together: one round trip per query.
//! The fake server's `pipe:` script withholds the RUN reply until the PULL
//! has arrived, so a client that waits in between times out.

#[path = "support/fake_bolt.rs"]
mod fake_bolt;

use std::collections::HashMap;
use std::time::Duration;

use boltwire::message::{PULL, RESET, RUN};
use boltwire::{BoltConnection, BoltError, BoltValue};
use fake_bolt::FakeBolt;

async fn connect(server: &FakeBolt) -> BoltConnection {
    let mut conn = BoltConnection::connect(server.addr(), None)
        .await
        .expect("connect");
    conn.set_read_timeout(Duration::from_secs(2));
    conn
}

/// Signatures after HELLO and LOGON.
fn requests(server: &FakeBolt) -> Vec<u8> {
    server.signatures(0)[2..].to_vec()
}

#[tokio::test]
async fn autocommit_run_pipelines_pull() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;
    let result = conn
        .run("pipe:q", HashMap::new())
        .await
        .expect("RUN and PULL sent together");
    assert_eq!(result.columns, vec!["q".to_string()]);
    assert_eq!(result.records, vec![vec![BoltValue::from("pipe:q")]]);
}

#[tokio::test]
async fn transaction_run_pipelines_pull() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;
    let mut tx = conn.begin().await.expect("begin");
    let result = tx.run("pipe:q", HashMap::new()).await.expect("pipelined");
    assert_eq!(result.records, vec![vec![BoltValue::from("pipe:q")]]);
    tx.commit().await.expect("commit");
}

#[tokio::test]
async fn stream_pipelines_its_first_batch() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;
    let mut stream = conn
        .run_stream("pipe:q", HashMap::new(), 10)
        .await
        .expect("RUN and first PULL sent together");
    assert_eq!(stream.columns(), ["q"]);
    let row = stream.next().await.expect("row").expect("one row");
    assert_eq!(row, vec![BoltValue::from("pipe:q")]);
    assert!(stream.next().await.expect("end").is_none());
}

#[tokio::test]
async fn stream_batches_continue_after_the_pipelined_one() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;
    let mut stream = conn
        .run_stream("rows:5:q", HashMap::new(), 2)
        .await
        .expect("stream");
    let mut seen = Vec::new();
    while let Some(row) = stream.next().await.expect("row") {
        seen.push(row[1].as_int().expect("index"));
    }
    assert_eq!(seen, vec![0, 1, 2, 3, 4]);
    drop(stream);
    // RUN + PULL(2) together, then PULL(2) twice more.
    assert_eq!(requests(&server), vec![RUN, PULL, PULL, PULL]);
    assert!(conn.is_ready());
}

#[tokio::test]
async fn run_failure_drains_the_ignored_pull_then_resets() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;

    let err = conn
        .run("fail:q", HashMap::new())
        .await
        .expect_err("scripted failure");
    assert!(
        matches!(&err, BoltError::Failure { code, .. } if code.contains("SyntaxError")),
        "{err:?}"
    );
    assert!(conn.is_ready());
    // The PULL was already on its way; the server IGNOREs it, then RESET.
    assert_eq!(requests(&server), vec![RUN, PULL, RESET]);

    let result = conn.run("after", HashMap::new()).await.expect("in sync");
    assert_eq!(result.records, vec![vec![BoltValue::from("after")]]);
}

#[tokio::test]
async fn stream_run_failure_drains_the_ignored_pull() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;

    let err = conn
        .run_stream("fail:q", HashMap::new(), 10)
        .await
        .err()
        .expect("scripted failure");
    assert!(matches!(err, BoltError::Failure { .. }), "{err:?}");
    assert!(conn.is_ready());

    let result = conn.run("after", HashMap::new()).await.expect("in sync");
    assert_eq!(result.records, vec![vec![BoltValue::from("after")]]);
}

#[tokio::test]
async fn pull_failure_surfaces_and_resets() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;

    let err = conn
        .run("pullfail:q", HashMap::new())
        .await
        .expect_err("scripted PULL failure");
    assert!(
        matches!(&err, BoltError::Failure { message, .. } if message == "pull boom"),
        "{err:?}"
    );
    assert!(conn.is_ready());
    let result = conn.run("after", HashMap::new()).await.expect("in sync");
    assert_eq!(result.records, vec![vec![BoltValue::from("after")]]);
}

#[tokio::test]
async fn failed_statement_in_a_transaction_kills_it_cleanly() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;
    let mut tx = conn.begin().await.expect("begin");
    let err = tx.run("fail:q", HashMap::new()).await.expect_err("failure");
    assert!(matches!(err, BoltError::Failure { .. }), "{err:?}");
    assert!(tx.run("next", HashMap::new()).await.is_err(), "tx is dead");
    tx.rollback()
        .await
        .expect("rollback of a dead tx is a no-op");

    let result = conn.run("after", HashMap::new()).await.expect("in sync");
    assert_eq!(result.records, vec![vec![BoltValue::from("after")]]);
}

#[tokio::test]
async fn finish_with_the_first_batch_in_flight_discards_the_rest() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;
    let stream = conn
        .run_stream("rows:5:q", HashMap::new(), 2)
        .await
        .expect("stream");
    stream.finish().await.expect("finish");
    assert!(conn.is_ready());
    assert_eq!(
        requests(&server),
        vec![RUN, PULL, boltwire::message::DISCARD]
    );
    let result = conn.run("after", HashMap::new()).await.expect("in sync");
    assert_eq!(result.records, vec![vec![BoltValue::from("after")]]);
}

#[tokio::test]
async fn finish_after_a_complete_first_batch_returns_its_summary() {
    let server = FakeBolt::start().await;
    let mut conn = connect(&server).await;
    let stream = conn
        .run_stream("rows:1:q", HashMap::new(), 10)
        .await
        .expect("stream");
    let summary = stream.finish().await.expect("finish");
    assert_eq!(summary.get("has_more"), Some(&BoltValue::Bool(false)));
    assert!(conn.is_ready());
    assert_eq!(
        requests(&server),
        vec![RUN, PULL],
        "nothing left to DISCARD"
    );
}
