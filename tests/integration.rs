//! Live integration tests against a real Bolt server.
//!
//! Gated on `BOLT_ADDR` so `cargo test` stays green with no server. Run with:
//!
//! ```sh
//! BOLT_ADDR=127.0.0.1:17688 BOLT_USER=memgraph BOLT_PASS=activecypher \
//!   cargo test --test integration -- --nocapture
//! ```

use std::collections::HashMap;

use boltwire::{Auth, BoltConnection, BoltValue};

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
    BoltConnection::connect(addr, auth)
        .await
        .expect("connect failed")
}

#[tokio::test]
async fn handshake_and_scalar_query() {
    let Some(_) = config() else {
        eprintln!("skipping: BOLT_ADDR unset");
        return;
    };
    let mut conn = connect().await;
    eprintln!(
        "negotiated Bolt {}, server={:?}",
        conn.version(),
        conn.server_agent()
    );

    let result = conn
        .run("RETURN 1 AS n", HashMap::new())
        .await
        .expect("query failed");
    assert_eq!(result.columns, vec!["n".to_string()]);
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0][0], BoltValue::Int(1));

    conn.close().await.expect("close failed");
}

#[tokio::test]
async fn parameterized_query_and_types() {
    let Some(_) = config() else {
        eprintln!("skipping: BOLT_ADDR unset");
        return;
    };
    let mut conn = connect().await;

    let mut params = HashMap::new();
    params.insert("name".to_string(), BoltValue::String("Neo".into()));
    params.insert("n".to_string(), BoltValue::Int(42));

    let result = conn
        .run(
            "RETURN $name AS name, $n AS n, [1, 2.5, true, null] AS mixed",
            params,
        )
        .await
        .expect("query failed");

    assert_eq!(
        result.columns,
        vec!["name".to_string(), "n".to_string(), "mixed".to_string()]
    );
    let row = &result.records[0];
    assert_eq!(row[0], BoltValue::String("Neo".into()));
    assert_eq!(row[1], BoltValue::Int(42));
    assert_eq!(
        row[2],
        BoltValue::List(vec![
            BoltValue::Int(1),
            BoltValue::Float(2.5),
            BoltValue::Bool(true),
            BoltValue::Null,
        ])
    );
    conn.close().await.expect("close failed");
}

#[tokio::test]
async fn node_structure_roundtrip() {
    let Some(_) = config() else {
        eprintln!("skipping: BOLT_ADDR unset");
        return;
    };
    let mut conn = connect().await;

    // Create then read back a node; it arrives as a PackStream Structure.
    let result = conn
        .run(
            "CREATE (p:Person {name: 'Trinity'}) RETURN p",
            HashMap::new(),
        )
        .await
        .expect("query failed");

    match &result.records[0][0] {
        BoltValue::Structure { signature, fields } => {
            assert_eq!(
                *signature,
                boltwire::value::sig::NODE,
                "expected Node signature"
            );
            assert!(!fields.is_empty(), "node should carry id/labels/props");
            eprintln!("node fields: {fields:?}");
        }
        other => panic!("expected Node structure, got {other:?}"),
    }

    // Clean up so reruns stay deterministic.
    conn.run(
        "MATCH (p:Person {name: 'Trinity'}) DELETE p",
        HashMap::new(),
    )
    .await
    .expect("cleanup failed");
    conn.close().await.expect("close failed");
}

#[tokio::test]
async fn bad_cypher_surfaces_failure() {
    let Some(_) = config() else {
        eprintln!("skipping: BOLT_ADDR unset");
        return;
    };
    let mut conn = connect().await;
    let err = conn
        .run("THIS IS NOT CYPHER", HashMap::new())
        .await
        .unwrap_err();
    match err {
        boltwire::BoltError::Failure { code, message } => {
            eprintln!("expected failure surfaced: {code} - {message}");
        }
        other => panic!("expected Failure, got {other:?}"),
    }
    // Connection must remain usable after a handled failure (RESET worked).
    let ok = conn
        .run("RETURN 1 AS n", HashMap::new())
        .await
        .expect("post-failure query failed");
    assert_eq!(ok.records[0][0], BoltValue::Int(1));
    conn.close().await.expect("close failed");
}
