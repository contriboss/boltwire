// Live tests for transactions, pooling, and routing. Gated on BOLT_ADDR.
//
//   BOLT_ADDR=127.0.0.1:17688 BOLT_USER=memgraph BOLT_PASS=activecypher \
//     cargo test --test features_live -- --test-threads=1

use std::collections::HashMap;

use boltwire::{Auth, BoltConnection, BoltValue, Pool, RoutedPool, TxOptions};

fn config() -> Option<(String, Option<Auth>)> {
    let addr = std::env::var("BOLT_ADDR").ok()?;
    let auth = match (std::env::var("BOLT_USER"), std::env::var("BOLT_PASS")) {
        (Ok(u), Ok(p)) => Some(Auth::basic(u, p)),
        _ => None,
    };
    Some((addr, auth))
}

async fn connect() -> BoltConnection {
    let (addr, auth) = config().expect("BOLT_ADDR unset");
    BoltConnection::connect(addr, auth).await.expect("connect failed")
}

fn is_neo4j(conn: &BoltConnection) -> bool {
    // Memgraph reports "... - Memgraph"; real Neo4j is plain "Neo4j/x.y".
    !conn.server_agent().unwrap_or_default().contains("Memgraph")
}

async fn cleanup(conn: &mut BoltConnection, label: &str) {
    let q = format!("MATCH (n:{label}) DETACH DELETE n");
    conn.run(&q, HashMap::new()).await.unwrap();
}

#[tokio::test]
async fn tx_commit_persists() {
    let Some(_) = config() else { return };
    let mut conn = connect().await;
    cleanup(&mut conn, "TxCommit").await;

    let mut tx = conn.begin().await.unwrap();
    tx.run("CREATE (:TxCommit {n: 1})", HashMap::new()).await.unwrap();
    tx.run("CREATE (:TxCommit {n: 2})", HashMap::new()).await.unwrap();
    let bookmark = tx.commit().await.unwrap();
    eprintln!("commit bookmark: {bookmark:?}");

    assert_eq!(count(&mut conn, "TxCommit").await, 2);
    cleanup(&mut conn, "TxCommit").await;
    conn.close().await.unwrap();
}

#[tokio::test]
async fn tx_rollback_discards() {
    let Some(_) = config() else { return };
    let mut conn = connect().await;
    cleanup(&mut conn, "TxRollback").await;

    let mut tx = conn.begin().await.unwrap();
    tx.run("CREATE (:TxRollback {n: 1})", HashMap::new()).await.unwrap();
    tx.rollback().await.unwrap();

    assert_eq!(count(&mut conn, "TxRollback").await, 0);
    conn.close().await.unwrap();
}

#[tokio::test]
async fn tx_drop_aborts() {
    let Some(_) = config() else { return };
    let mut conn = connect().await;
    cleanup(&mut conn, "TxDrop").await;

    {
        let mut tx = conn.begin().await.unwrap();
        tx.run("CREATE (:TxDrop {n: 1})", HashMap::new()).await.unwrap();
        // dropped without commit
    }

    // Next op RESETs first; the write must be gone.
    assert_eq!(count(&mut conn, "TxDrop").await, 0);
    conn.close().await.unwrap();
}

#[tokio::test]
async fn tx_failed_statement_kills_tx() {
    let Some(_) = config() else { return };
    let mut conn = connect().await;

    let mut tx = conn.begin().await.unwrap();
    assert!(tx.run("NOT CYPHER", HashMap::new()).await.is_err());
    // tx is dead: commit must error client-side, rollback is a no-op.
    assert!(tx.commit().await.is_err());

    // Connection remains usable.
    let r = conn.run("RETURN 1 AS n", HashMap::new()).await.unwrap();
    assert_eq!(r.records[0][0], BoltValue::Int(1));
    conn.close().await.unwrap();
}

#[tokio::test]
async fn tx_read_only_option() {
    let Some(_) = config() else { return };
    let mut conn = connect().await;
    // Memgraph ignores mode; Neo4j routes/validates it. Either way BEGIN must succeed.
    let mut tx =
        conn.begin_with(TxOptions { read_only: true, ..Default::default() }).await.unwrap();
    let r = tx.run("RETURN 42 AS n", HashMap::new()).await.unwrap();
    assert_eq!(r.records[0][0], BoltValue::Int(42));
    tx.commit().await.unwrap();
    conn.close().await.unwrap();
}

#[tokio::test]
async fn pool_reuses_and_bounds_connections() {
    let Some((addr, auth)) = config() else { return };
    let pool = Pool::new(2, move || {
        let addr = addr.clone();
        let auth = auth.clone();
        async move { BoltConnection::connect(addr, auth).await }
    });

    // Checkout, use, return.
    let id_first = {
        let mut conn = pool.get().await.unwrap();
        let r = conn.run("RETURN 1 AS n", HashMap::new()).await.unwrap();
        assert_eq!(r.records[0][0], BoltValue::Int(1));
        conn.connection_id().map(ToString::to_string)
    };

    // Same underlying connection comes back (idle reuse).
    let conn = pool.get().await.unwrap();
    assert_eq!(conn.connection_id().map(ToString::to_string), id_first);
    drop(conn);

    // max_size=2 under 8 concurrent users: everything completes.
    let mut handles = Vec::new();
    for i in 0..8 {
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            let mut conn = pool.get().await.unwrap();
            let r = conn.run("RETURN $i AS n", params_i(i)).await.unwrap();
            assert_eq!(r.records[0][0], BoltValue::Int(i));
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

fn params_i(i: i64) -> HashMap<String, BoltValue> {
    let mut p = HashMap::new();
    p.insert("i".to_string(), BoltValue::Int(i));
    p
}

#[tokio::test]
async fn tx_stream_with_qid() {
    let Some(_) = config() else { return };
    let mut conn = connect().await;
    cleanup(&mut conn, "TxStream").await;

    let mut tx = conn.begin().await.unwrap();
    tx.run("UNWIND range(1, 500) AS x CREATE (:TxStream {n: x})", HashMap::new()).await.unwrap();

    // First cursor: stream uncommitted rows in batches.
    let mut stream = tx
        .run_stream("MATCH (t:TxStream) RETURN t.n ORDER BY t.n", HashMap::new(), 64)
        .await
        .unwrap();
    let mut seen = 0i64;
    let mut last = 0i64;
    while let Some(row) = stream.next().await.unwrap() {
        seen += 1;
        last = row[0].as_int().unwrap();
    }
    stream.finish().await.unwrap();
    assert_eq!((seen, last), (500, 500));

    // Second sequential cursor in the same tx, abandoned early via finish().
    let mut stream =
        tx.run_stream("MATCH (t:TxStream) RETURN t.n", HashMap::new(), 10).await.unwrap();
    assert!(stream.next().await.unwrap().is_some());
    stream.finish().await.unwrap();

    tx.rollback().await.unwrap();
    assert_eq!(count(&mut conn, "TxStream").await, 0);
    conn.close().await.unwrap();
}

async fn count(conn: &mut BoltConnection, label: &str) -> i64 {
    let q = format!("MATCH (n:{label}) RETURN count(n) AS c");
    conn.run(&q, HashMap::new()).await.unwrap().records[0][0].as_int().unwrap()
}

#[tokio::test]
async fn node_view_on_live_row() {
    let Some(_) = config() else { return };
    let mut conn = connect().await;
    cleanup(&mut conn, "ViewTest").await;
    let r = conn.run("CREATE (v:ViewTest {k: 9}) RETURN v", HashMap::new()).await.unwrap();
    let node = r.records[0][0].as_node().expect("row should view as node");
    assert!(node.label_strs().contains(&"ViewTest"));
    assert_eq!(node.prop("k").and_then(BoltValue::as_int), Some(9));
    cleanup(&mut conn, "ViewTest").await;
    conn.close().await.unwrap();
}

#[tokio::test]
async fn stream_batches_all_records() {
    let Some(_) = config() else { return };
    let mut conn = connect().await;

    // 10000 rows through 256-row batches: forces ~40 PULL round-trips.
    let mut stream =
        conn.run_stream("UNWIND range(1, 10000) AS x RETURN x", HashMap::new(), 256).await.unwrap();
    assert_eq!(stream.columns(), ["x"]);

    let (mut count, mut sum) = (0i64, 0i64);
    while let Some(row) = stream.next().await.unwrap() {
        count += 1;
        sum += row[0].as_int().unwrap();
    }
    stream.finish().await.unwrap();
    assert_eq!(count, 10_000);
    assert_eq!(sum, 50_005_000);
    conn.close().await.unwrap();
}

#[tokio::test]
async fn stream_batch_of_one() {
    let Some(_) = config() else { return };
    let mut conn = connect().await;
    let mut stream =
        conn.run_stream("UNWIND range(1, 5) AS x RETURN x", HashMap::new(), 1).await.unwrap();
    let mut seen = Vec::new();
    while let Some(row) = stream.next().await.unwrap() {
        seen.push(row[0].as_int().unwrap());
    }
    stream.finish().await.unwrap();
    assert_eq!(seen, [1, 2, 3, 4, 5]);
    conn.close().await.unwrap();
}

#[tokio::test]
async fn stream_finish_discards_remainder() {
    let Some(_) = config() else { return };
    let mut conn = connect().await;
    let mut stream =
        conn.run_stream("UNWIND range(1, 100000) AS x RETURN x", HashMap::new(), 10).await.unwrap();
    // Take three, abandon the other 99,997 politely.
    for _ in 0..3 {
        assert!(stream.next().await.unwrap().is_some());
    }
    stream.finish().await.unwrap();

    // Connection immediately usable, no RESET needed.
    let r = conn.run("RETURN 7 AS n", HashMap::new()).await.unwrap();
    assert_eq!(r.records[0][0], BoltValue::Int(7));
    conn.close().await.unwrap();
}

#[tokio::test]
async fn stream_drop_recovers() {
    let Some(_) = config() else { return };
    let mut conn = connect().await;
    {
        let mut stream = conn
            .run_stream("UNWIND range(1, 100000) AS x RETURN x", HashMap::new(), 10)
            .await
            .unwrap();
        let _ = stream.next().await.unwrap();
        // dropped rudely, mid-stream
    }
    // Next op RESETs first.
    let r = conn.run("RETURN 8 AS n", HashMap::new()).await.unwrap();
    assert_eq!(r.records[0][0], BoltValue::Int(8));
    conn.close().await.unwrap();
}

#[tokio::test]
async fn routed_pool_single_node() {
    let Some((addr, auth)) = config() else { return };
    // Only meaningful where ROUTE is spoken.
    {
        let conn = connect().await;
        if !is_neo4j(&conn) {
            eprintln!("skipping: server does not speak ROUTE");
            return;
        }
        conn.close().await.unwrap();
    }

    let pool = RoutedPool::new(vec![addr.clone()], None, 2, move |server| {
        // Single node advertises "localhost:7687" (its cluster address);
        // dial the mapped test port instead for any advertised address.
        let addr = addr.clone();
        let auth = auth.clone();
        async move {
            let _ = server; // one node: every role resolves to the same box
            BoltConnection::connect(addr, auth).await
        }
    });

    let table = pool.table().await.unwrap();
    eprintln!("routed table: {table:?}");
    assert!(!table.writers.is_empty());

    let mut w = pool.write().await.unwrap();
    let r = w.run("RETURN 1 AS n", HashMap::new()).await.unwrap();
    assert_eq!(r.records[0][0], BoltValue::Int(1));
    drop(w);

    let mut rd = pool.read().await.unwrap();
    let r = rd.run("RETURN 2 AS n", HashMap::new()).await.unwrap();
    assert_eq!(r.records[0][0], BoltValue::Int(2));
}

#[tokio::test]
async fn managed_tx_retries_and_threads_bookmarks() {
    let Some((addr, auth)) = config() else { return };
    {
        let conn = connect().await;
        if !is_neo4j(&conn) {
            return; // managed tx rides the routed pool; needs ROUTE
        }
        conn.close().await.unwrap();
    }

    let dial_addr = addr.clone();
    let pool = RoutedPool::new(vec![addr], None, 2, move |_server| {
        let addr = dial_addr.clone();
        let auth = auth.clone();
        async move { BoltConnection::connect(addr, auth).await }
    });

    let n = pool
        .execute_write(|tx| {
            Box::pin(async move {
                tx.run(
                    "MERGE (c:RetryTest {id: 1}) SET c.hits = coalesce(c.hits, 0) + 1",
                    HashMap::new(),
                )
                .await?;
                Ok(1)
            })
        })
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert!(!pool.bookmarks().await.is_empty(), "commit bookmark must be captured");

    let hits = pool
        .execute_read(|tx| {
            Box::pin(async move {
                let r = tx.run("MATCH (c:RetryTest {id: 1}) RETURN c.hits", HashMap::new()).await?;
                Ok(r.records[0][0].as_int().unwrap())
            })
        })
        .await
        .unwrap();
    assert!(hits >= 1);

    pool.execute_write(|tx| {
        Box::pin(async move {
            tx.run("MATCH (c:RetryTest) DELETE c", HashMap::new()).await?;
            Ok(())
        })
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn route_or_clean_failure() {
    let Some(_) = config() else { return };
    let mut conn = connect().await;

    let result = conn.route(HashMap::new(), None).await;
    if is_neo4j(&conn) {
        // Single instance answers with itself in every role.
        let table = result.expect("Neo4j must answer ROUTE");
        eprintln!("routing table: {table:?}");
        assert!(!table.writers.is_empty());
        assert!(table.ttl_seconds > 0);
    } else {
        // Memgraph doesn't speak ROUTE; must surface a clean failure and the
        // connection must stay usable.
        assert!(result.is_err());
        let r = conn.run("RETURN 1 AS n", HashMap::new()).await.unwrap();
        assert_eq!(r.records[0][0], BoltValue::Int(1));
    }
    conn.close().await.unwrap();
}
