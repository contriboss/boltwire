//! rustls backend (ring crypto). webpki roots by default.

use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{
    CryptoProvider, ring, verify_tls12_signature, verify_tls13_signature,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use super::{BoltStream, TlsHandshake, TlsProvider};
use crate::error::{BoltError, Result};

pub struct RustlsProvider {
    connector: TlsConnector,
}

impl RustlsProvider {
    #[must_use]
    pub fn builder() -> RustlsProviderBuilder {
        RustlsProviderBuilder::default()
    }
}

#[derive(Default)]
pub struct RustlsProviderBuilder {
    extra_roots_pem: Vec<Vec<u8>>,
    accept_invalid: bool,
    native_roots: bool,
    identity: Option<(Vec<u8>, Vec<u8>)>,
}

impl RustlsProviderBuilder {
    /// Extra PEM trust roots on top of webpki (pin a private CA / self-signed cert).
    #[must_use]
    pub fn add_root_pem(mut self, pem: &[u8]) -> Self {
        self.extra_roots_pem.push(pem.to_vec());
        self
    }

    /// Skip cert verification. Encrypted, unauthenticated.
    #[must_use]
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.accept_invalid = accept;
        self
    }

    /// Add the OS trust store on top of the webpki roots.
    #[must_use]
    pub fn use_native_roots(mut self) -> Self {
        self.native_roots = true;
        self
    }

    /// Present a client certificate (mutual TLS). Both arguments are PEM.
    #[must_use]
    pub fn client_identity(mut self, cert_chain_pem: &[u8], key_pem: &[u8]) -> Self {
        self.identity = Some((cert_chain_pem.to_vec(), key_pem.to_vec()));
        self
    }

    pub fn build(self) -> Result<RustlsProvider> {
        let builder = if self.accept_invalid {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerification::new()))
        } else {
            let mut roots = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            if self.native_roots {
                for cert in rustls_native_certs::load_native_certs().certs {
                    roots.add(cert).ok();
                }
            }
            for pem in &self.extra_roots_pem {
                for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
                    let cert =
                        cert.map_err(|e| BoltError::Tls(format!("invalid PEM root: {e}")))?;
                    roots
                        .add(cert)
                        .map_err(|e| BoltError::Tls(format!("unusable PEM root: {e}")))?;
                }
            }
            ClientConfig::builder().with_root_certificates(roots)
        };

        let config = match self.identity {
            Some((cert_pem, key_pem)) => {
                let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| BoltError::Tls(format!("invalid client cert: {e}")))?;
                let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
                    .map_err(|e| BoltError::Tls(format!("invalid client key: {e}")))?
                    .ok_or_else(|| BoltError::Tls("no private key in PEM".into()))?;
                builder
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| BoltError::Tls(format!("client identity rejected: {e}")))?
            }
            None => builder.with_no_client_auth(),
        };

        Ok(RustlsProvider {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }
}

impl TlsProvider for RustlsProvider {
    fn connect<'a>(&'a self, server_name: &'a str, tcp: TcpStream) -> TlsHandshake<'a> {
        Box::pin(async move {
            let name = ServerName::try_from(server_name.to_string())
                .map_err(|e| BoltError::Tls(format!("invalid server name {server_name:?}: {e}")))?;
            let stream = self
                .connector
                .connect(name, tcp)
                .await
                .map_err(|e| BoltError::Tls(format!("handshake with {server_name}: {e}")))?;
            Ok(Box::new(stream) as Box<dyn BoltStream>)
        })
    }
}

/// Accepts any cert; signatures still checked against it.
#[derive(Debug)]
struct NoVerification {
    provider: CryptoProvider,
}

impl NoVerification {
    fn new() -> Self {
        Self {
            provider: ring::default_provider(),
        }
    }
}

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
