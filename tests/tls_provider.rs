//! The rustls backend must not depend on rustls's process-wide default
//! crypto provider. A program that links both ring and aws-lc-rs and never
//! installs a default made `RustlsProviderBuilder::build` panic.
//!
//! Its own test binary: it installs a process default on purpose.
#![cfg(feature = "tls-rustls")]

#[path = "support/fake_bolt.rs"]
mod fake_bolt;
#[path = "support/pki.rs"]
mod pki;

use std::collections::HashMap;
use std::sync::Arc;

use boltwire::{BoltConnection, BoltValue, RustlsProvider};
use fake_bolt::{FakeBolt, Options};
use tokio_rustls::rustls::crypto::{CryptoProvider, ring};

/// A process default no TLS client can use: it has no cipher suites. Code
/// that silently picks up the default fails here just as it panics when
/// rustls cannot choose between ring and aws-lc-rs.
fn install_unusable_default() {
    let unusable = CryptoProvider {
        cipher_suites: Vec::new(),
        ..ring::default_provider()
    };
    // Ignore "already installed": the tests below share this process.
    let _ = unusable.install_default();
}

#[tokio::test]
async fn provider_uses_ring_regardless_of_the_process_default() {
    install_unusable_default();
    let pki = pki::pki();
    let server = FakeBolt::start_with(Options {
        tls: Some(Arc::clone(&pki.server)),
        ..Options::default()
    })
    .await;

    let tls = RustlsProvider::builder()
        .add_root_pem(pki.ca_pem.as_bytes())
        .build()
        .expect("builds with ring, not the process default");
    let mut conn = BoltConnection::connect_tls(server.addr(), "localhost", None, &tls)
        .await
        .expect("TLS handshake with the private CA");
    let result = conn.run("over-tls", HashMap::new()).await.expect("query");
    assert_eq!(result.records, vec![vec![BoltValue::from("over-tls")]]);
}

#[test]
fn accept_invalid_provider_uses_ring_regardless_of_the_process_default() {
    install_unusable_default();
    RustlsProvider::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("builds with ring, not the process default");
}
