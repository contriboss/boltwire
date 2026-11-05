//! Pool behaviour against a scripted fake server; no database needed.

#[path = "support/fake_bolt.rs"]
mod fake_bolt;

use std::collections::HashMap;
use std::sync::Arc;

use boltwire::{BoltConnection, Pool};
use fake_bolt::FakeBolt;

fn pool(server: &FakeBolt, size: usize) -> Pool {
    let addr = server.addr();
    Pool::new(size, move || {
        let addr = addr.clone();
        async move { BoltConnection::connect(addr, None).await }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn returns_are_not_lost_under_contention() {
    const SIZE: usize = 4;
    let server = FakeBolt::start().await;
    let pool = Arc::new(pool(&server, SIZE));

    let tasks: Vec<_> = (0..32)
        .map(|_| {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move {
                for _ in 0..100 {
                    let mut conn = pool.get().await.expect("checkout");
                    conn.run("q", HashMap::new()).await.expect("query");
                }
            })
        })
        .collect();
    for task in tasks {
        task.await.expect("task");
    }

    // Every connection went back to the pool, so no more than SIZE were
    // ever opened.
    assert!(
        server.accepted() <= SIZE,
        "{} connections opened for a pool of {SIZE}",
        server.accepted()
    );
}
