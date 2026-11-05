//! rustls trust configuration against a TLS fake server; no database.
#![cfg(feature = "tls-rustls")]

#[path = "support/fake_bolt.rs"]
mod fake_bolt;
#[path = "support/pki.rs"]
mod pki;

use std::collections::HashMap;
use std::sync::Arc;

use boltwire::tls::rustls::RootCertStore;
use boltwire::{BoltConnection, BoltError, BoltValue, RustlsProvider};
use fake_bolt::{FakeBolt, Options};
use tokio_rustls::rustls::ServerConfig;

async fn tls_server(config: &Arc<ServerConfig>) -> FakeBolt {
    FakeBolt::start_with(Options {
        tls: Some(Arc::clone(config)),
        ..Options::default()
    })
    .await
}

async fn query_over(server: &FakeBolt, tls: &RustlsProvider) -> Result<(), BoltError> {
    let mut conn = BoltConnection::connect_tls(server.addr(), "localhost", None, tls).await?;
    let result = conn.run("tls", HashMap::new()).await?;
    assert_eq!(result.records, vec![vec![BoltValue::from("tls")]]);
    Ok(())
}

#[tokio::test]
async fn private_ca_alone_is_trusted_with_an_empty_root_store() {
    let pki = pki::pki();
    let server = tls_server(&pki.server).await;
    let tls = RustlsProvider::builder()
        .with_root_store(RootCertStore::empty())
        .add_root_pem(pki.ca_pem.as_bytes())
        .build()
        .expect("provider");
    query_over(&server, &tls).await.expect("private CA trusted");
}

#[tokio::test]
async fn empty_root_store_trusts_nothing() {
    let pki = pki::pki();
    let server = tls_server(&pki.server).await;
    let tls = RustlsProvider::builder()
        .with_root_store(RootCertStore::empty())
        .build()
        .expect("provider");
    let err = query_over(&server, &tls).await.expect_err("no roots");
    assert!(
        matches!(&err, BoltError::Tls(m) if m.contains("UnknownIssuer")),
        "{err:?}"
    );
}

#[tokio::test]
async fn custom_root_store_is_used() {
    let pki = pki::pki();
    let server = tls_server(&pki.server).await;
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca_der.clone()).expect("CA usable as root");
    let tls = RustlsProvider::builder()
        .with_root_store(roots)
        .build()
        .expect("provider");
    query_over(&server, &tls)
        .await
        .expect("custom store trusted");
}

#[tokio::test]
async fn der_roots_are_accepted() {
    let pki = pki::pki();
    let server = tls_server(&pki.server).await;
    let tls = RustlsProvider::builder()
        .add_root_der(pki.ca_der.as_ref())
        .build()
        .expect("provider");
    query_over(&server, &tls).await.expect("DER root trusted");
}

#[tokio::test]
async fn ca_style_self_signed_cert_fails_as_a_root_but_can_be_pinned() {
    let cert = pki::self_signed_ca_style();
    let server = tls_server(&cert.server).await;

    let as_root = RustlsProvider::builder()
        .add_root_pem(cert.cert_pem.as_bytes())
        .build()
        .expect("provider");
    let err = query_over(&server, &as_root)
        .await
        .expect_err("webpki refuses a CA cert as the end entity");
    assert!(
        matches!(&err, BoltError::Tls(m) if m.contains("CaUsedAsEndEntity")),
        "{err:?}"
    );

    let pinned = RustlsProvider::builder()
        .pin_certificate_pem(cert.cert_pem.as_bytes())
        .build()
        .expect("provider");
    query_over(&server, &pinned)
        .await
        .expect("pinned cert trusted");
}

#[tokio::test]
async fn pinning_rejects_any_other_certificate() {
    let cert = pki::self_signed_ca_style();
    let other = pki::self_signed_ca_style();
    let server = tls_server(&cert.server).await;
    let tls = RustlsProvider::builder()
        .pin_certificate_pem(other.cert_pem.as_bytes())
        .build()
        .expect("provider");
    let err = query_over(&server, &tls).await.expect_err("wrong pin");
    assert!(matches!(err, BoltError::Tls(_)), "{err:?}");
}

#[test]
fn pinning_rejects_pem_without_certificates() {
    let err = RustlsProvider::builder()
        .pin_certificate_pem(b"not a certificate")
        .build()
        .err()
        .expect("nothing to pin");
    assert!(matches!(err, BoltError::Tls(_)), "{err:?}");
}
