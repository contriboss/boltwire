// Derive-in, derive-out against a live server. Gated on BOLT_ADDR.
#![cfg(feature = "serde")]

use boltwire::{Auth, BoltConnection, params};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct In {
    name: String,
    age: i64,
}

#[derive(Deserialize, Debug, PartialEq)]
struct Out {
    name: String,
    doubled: i64,
}

#[tokio::test]
async fn derive_roundtrip() {
    let Ok(addr) = std::env::var("BOLT_ADDR") else {
        return;
    };
    let auth = match (std::env::var("BOLT_USER"), std::env::var("BOLT_PASS")) {
        (Ok(u), Ok(p)) => Some(Auth::basic(u, p)),
        _ => None,
    };
    let mut conn = BoltConnection::connect(addr, auth).await.unwrap();

    let p = params(&In { name: "Trin".into(), age: 21 }).unwrap();
    let result = conn.run("RETURN $name AS name, $age * 2 AS doubled", p).await.unwrap();
    let rows: Vec<Out> = result.rows_as().unwrap();
    assert_eq!(rows, vec![Out { name: "Trin".into(), doubled: 42 }]);
    conn.close().await.unwrap();
}
