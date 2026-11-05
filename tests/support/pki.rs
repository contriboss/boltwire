//! Throwaway PKI for TLS tests: a private CA and a `localhost` leaf it signs.

#![allow(dead_code)]

use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub struct Pki {
    /// The private CA certificate, PEM.
    pub ca_pem: String,
    /// The CA certificate, DER.
    pub ca_der: CertificateDer<'static>,
    /// A server config presenting the leaf (valid for `localhost`).
    pub server: Arc<ServerConfig>,
}

#[must_use]
pub fn pki() -> Pki {
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "boltwire test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA cert");
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf cert");

    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    // Explicit provider: never depend on a process default in tests either.
    let server = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], key)
        .expect("server cert");

    Pki {
        ca_pem: ca_cert.pem(),
        ca_der: ca_cert.der().clone(),
        server: Arc::new(server),
    }
}
