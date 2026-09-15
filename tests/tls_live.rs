// Live TLS tests via the stunnel sidecar (tests/support/tls-sidecar.sh up).
// Gated on BOLT_TLS_ADDR; skipped when unset.
#![cfg(feature = "tls-rustls")]

use std::collections::HashMap;

use boltwire::{Auth, BoltConnection, BoltError, BoltValue, RustlsProvider};

struct Cfg {
    addr: String,
    server_name: String,
    ca_pem: Vec<u8>,
    auth: Option<Auth>,
}

fn cfg() -> Option<Cfg> {
    let addr = std::env::var("BOLT_TLS_ADDR").ok()?;
    let server_name = std::env::var("BOLT_TLS_SERVERNAME").unwrap_or_else(|_| "localhost".into());
    let ca_pem = std::fs::read(std::env::var("BOLT_TLS_CA").ok()?).ok()?;
    let auth = match (std::env::var("BOLT_USER"), std::env::var("BOLT_PASS")) {
        (Ok(u), Ok(p)) => Some(Auth::basic(u, p)),
        _ => None,
    };
    Some(Cfg {
        addr,
        server_name,
        ca_pem,
        auth,
    })
}

#[tokio::test]
async fn strict_with_pinned_root() {
    let Some(c) = cfg() else { return };
    let tls = RustlsProvider::builder()
        .add_root_pem(&c.ca_pem)
        .build()
        .unwrap();

    let mut conn = BoltConnection::connect_tls(&c.addr, &c.server_name, c.auth, &tls)
        .await
        .expect("strict TLS with pinned root should connect");
    let result = conn.run("RETURN 1 AS n", HashMap::new()).await.unwrap();
    assert_eq!(result.records[0][0], BoltValue::Int(1));
    conn.close().await.unwrap();
}

#[tokio::test]
async fn strict_without_root_fails() {
    let Some(c) = cfg() else { return };
    // webpki roots only: the sidecar's self-signed cert must be rejected.
    let tls = RustlsProvider::builder().build().unwrap();

    match BoltConnection::connect_tls(&c.addr, &c.server_name, c.auth, &tls).await {
        Ok(_) => panic!("self-signed cert must fail strict verification"),
        Err(BoltError::Tls(msg)) => assert!(
            msg.to_lowercase().contains("certificate") || msg.contains("UnknownIssuer"),
            "unexpected TLS error: {msg}"
        ),
        Err(other) => panic!("expected Tls error, got {other:?}"),
    }
}

#[tokio::test]
async fn insecure_accepts_self_signed() {
    let Some(c) = cfg() else { return };
    let tls = RustlsProvider::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let mut conn = BoltConnection::connect_tls(&c.addr, &c.server_name, c.auth, &tls)
        .await
        .expect("insecure TLS should connect");

    let result = conn
        .run("CREATE (p:TlsTest {ok: true}) RETURN p", HashMap::new())
        .await
        .unwrap();
    assert!(matches!(result.records[0][0], BoltValue::Structure { .. }));
    conn.run("MATCH (p:TlsTest) DELETE p", HashMap::new())
        .await
        .unwrap();
    conn.close().await.unwrap();
}

#[tokio::test]
async fn mtls_requires_and_accepts_client_identity() {
    let Some(c) = cfg() else { return };
    let Ok(mtls_addr) = std::env::var("BOLT_MTLS_ADDR") else {
        return;
    };
    let cert = std::fs::read(std::env::var("BOLT_TLS_CLIENT_CERT").unwrap()).unwrap();
    let key = std::fs::read(std::env::var("BOLT_TLS_CLIENT_KEY").unwrap()).unwrap();

    // Without identity: stunnel must refuse the handshake or kill the socket.
    let bare = RustlsProvider::builder()
        .add_root_pem(&c.ca_pem)
        .build()
        .unwrap();
    assert!(
        BoltConnection::connect_tls(&mtls_addr, &c.server_name, c.auth.clone(), &bare)
            .await
            .is_err(),
        "mTLS listener accepted a client with no certificate"
    );

    // With identity: full Bolt roundtrip.
    let ident = RustlsProvider::builder()
        .add_root_pem(&c.ca_pem)
        .client_identity(&cert, &key)
        .build()
        .unwrap();
    let mut conn = BoltConnection::connect_tls(&mtls_addr, &c.server_name, c.auth, &ident)
        .await
        .expect("mTLS with identity should connect");
    let r = conn.run("RETURN 3 AS n", HashMap::new()).await.unwrap();
    assert_eq!(r.records[0][0], BoltValue::Int(3));
    conn.close().await.unwrap();
}
