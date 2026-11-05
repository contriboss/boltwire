//! URI-driven configuration against a scripted fake server; no database.
#![cfg(feature = "tls-rustls")]

#[path = "support/fake_bolt.rs"]
mod fake_bolt;
#[path = "support/pki.rs"]
mod pki;

use std::collections::HashMap;
use std::sync::Arc;

use boltwire::{BoltValue, Config};
use fake_bolt::{FakeBolt, Options};

#[tokio::test]
async fn routed_pool_handshakes_with_ipv6_servers() {
    let pki = pki::pki();
    let Some(server) = FakeBolt::bind(
        "[::1]:0",
        Options {
            tls: Some(Arc::clone(&pki.server)),
            ..Options::default()
        },
    )
    .await
    else {
        eprintln!("skipping: no IPv6 loopback");
        return;
    };
    // The routing table advertises "[::1]:port"; the TLS server name must
    // be "::1", not "[::1]".
    let config = Config::from_uri(&format!("neo4j+ssc://{}", server.addr())).expect("uri");
    let pool = config.routed_pool(1);

    let table = pool.table().await.expect("ROUTE over IPv6 TLS");
    assert_eq!(table.readers, vec![server.addr()]);
    let mut conn = pool.read().await.expect("reader over IPv6 TLS");
    let result = conn.run("v6", HashMap::new()).await.expect("query");
    assert_eq!(result.records, vec![vec![BoltValue::from("v6")]]);
}
