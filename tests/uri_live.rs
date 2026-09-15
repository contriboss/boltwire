// URI-driven connects against live servers. Gated on env like the other suites.
use std::collections::HashMap;

use boltwire::{BoltValue, Config};

fn creds() -> Option<(String, String)> {
    Some((
        std::env::var("BOLT_USER").ok()?,
        std::env::var("BOLT_PASS").ok()?,
    ))
}

#[tokio::test]
async fn bolt_uri_connects() {
    let Ok(addr) = std::env::var("BOLT_ADDR") else {
        return;
    };
    let Some((user, pass)) = creds() else { return };
    let mut conn = Config::from_uri(&format!("bolt://{user}:{pass}@{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let r = conn.run("RETURN 1 AS n", HashMap::new()).await.unwrap();
    assert_eq!(r.records[0][0], BoltValue::Int(1));
    conn.close().await.unwrap();
}

#[cfg(feature = "tls-rustls")]
#[tokio::test]
async fn bolt_ssc_uri_connects_via_sidecar() {
    let Ok(addr) = std::env::var("BOLT_TLS_ADDR") else {
        return;
    };
    let Some((user, pass)) = creds() else { return };
    // +ssc: encrypted, self-signed accepted. SNI uses the URI host (127.0.0.1).
    let mut conn = Config::from_uri(&format!("bolt+ssc://{user}:{pass}@{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let r = conn.run("RETURN 2 AS n", HashMap::new()).await.unwrap();
    assert_eq!(r.records[0][0], BoltValue::Int(2));
    conn.close().await.unwrap();
}

#[tokio::test]
async fn neo4j_uri_routes() {
    let Ok(addr) = std::env::var("BOLT_ROUTED_ADDR") else {
        return;
    };
    let Some((user, pass)) = creds() else { return };
    let config = Config::from_uri(&format!("neo4j://{user}:{pass}@{addr}")).unwrap();
    assert!(
        config.connect().await.is_err(),
        "routed scheme must refuse direct connect"
    );

    // Docker maps 7687 -> 17687, so the table's advertised addresses aren't
    // dialable here; prove URI -> pool -> ROUTE -> table works.
    let pool = config.routed_pool(2);
    let table = pool.table().await.unwrap();
    assert!(!table.writers.is_empty());
}
