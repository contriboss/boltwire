//! rustls backend (ring crypto). webpki roots by default.
//!
//! The ring provider is passed to rustls explicitly. rustls's process-wide
//! default is never consulted: it panics when a program links both ring and
//! aws-lc-rs and installs no default, and an installed one might not suit.

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
use tokio_rustls::rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme,
};

/// The rustls trust store type taken by
/// [`RustlsProviderBuilder::with_root_store`].
pub use tokio_rustls::rustls::RootCertStore;

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

/// Trust, from most to least specific: [`danger_accept_invalid_certs`]
/// accepts anything; otherwise pinned certificates, if any, are the only
/// ones accepted; otherwise the server chain is verified against the roots
/// (webpki's, or [`with_root_store`]'s, plus native and added ones).
///
/// [`danger_accept_invalid_certs`]: Self::danger_accept_invalid_certs
/// [`with_root_store`]: Self::with_root_store
#[derive(Default)]
pub struct RustlsProviderBuilder {
    root_store: Option<RootCertStore>,
    extra_roots_pem: Vec<Vec<u8>>,
    extra_roots_der: Vec<CertificateDer<'static>>,
    pins_pem: Vec<Vec<u8>>,
    pins_der: Vec<CertificateDer<'static>>,
    accept_invalid: bool,
    native_roots: bool,
    identity: Option<(Vec<u8>, Vec<u8>)>,
}

impl RustlsProviderBuilder {
    /// Extra PEM trust roots (a private CA) on top of the base roots.
    ///
    /// A self-signed server certificate works here only if it is not marked
    /// as a CA. One made by `openssl req -x509` usually is (`CA:TRUE`), and
    /// webpki refuses it as the server's own cert (`CaUsedAsEndEntity`);
    /// [pin](Self::pin_certificate_pem) such a certificate instead.
    #[must_use]
    pub fn add_root_pem(mut self, pem: &[u8]) -> Self {
        self.extra_roots_pem.push(pem.to_vec());
        self
    }

    /// Like [`add_root_pem`](Self::add_root_pem), for one DER certificate.
    #[must_use]
    pub fn add_root_der(mut self, der: &[u8]) -> Self {
        self.extra_roots_der
            .push(CertificateDer::from(der.to_vec()));
        self
    }

    /// Replace the base roots (webpki's by default) with `roots`. Roots
    /// from [`add_root_pem`](Self::add_root_pem) and
    /// [`use_native_roots`](Self::use_native_roots) are still added on top;
    /// `RootCertStore::empty()` plus a private CA trusts only that CA.
    #[must_use]
    pub fn with_root_store(mut self, roots: RootCertStore) -> Self {
        self.root_store = Some(roots);
        self
    }

    /// Accept exactly this server certificate (every one in the PEM), and
    /// no other. Chain, names and validity dates are not checked: the pinned
    /// certificate is the server's identity. The handshake signatures are
    /// still verified against its key. For self-signed servers.
    #[must_use]
    pub fn pin_certificate_pem(mut self, pem: &[u8]) -> Self {
        self.pins_pem.push(pem.to_vec());
        self
    }

    /// Like [`pin_certificate_pem`](Self::pin_certificate_pem), for one DER
    /// certificate.
    #[must_use]
    pub fn pin_certificate_der(mut self, der: &[u8]) -> Self {
        self.pins_der.push(CertificateDer::from(der.to_vec()));
        self
    }

    /// Skip cert verification. Encrypted, unauthenticated.
    #[must_use]
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.accept_invalid = accept;
        self
    }

    /// Add the OS trust store on top of the base roots.
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
        let crypto = Arc::new(ring::default_provider());
        let versions = ClientConfig::builder_with_provider(Arc::clone(&crypto))
            .with_safe_default_protocol_versions()
            .map_err(|e| BoltError::Tls(format!("ring provider unusable: {e}")))?;

        let mut pins = self.pins_der;
        for pem in &self.pins_pem {
            let before = pins.len();
            pins.extend(pem_certs(pem, "pinned certificate")?);
            if pins.len() == before {
                return Err(BoltError::Tls("no certificate in pinned PEM".into()));
            }
        }

        let trust = if self.accept_invalid {
            Some(Trust::Any)
        } else if !pins.is_empty() {
            Some(Trust::Pinned(pins))
        } else {
            None
        };
        let builder = if let Some(trust) = trust {
            versions
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(CustomVerifier {
                    trust,
                    provider: crypto,
                }))
        } else {
            let mut roots = self.root_store.unwrap_or_else(|| RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            });
            if self.native_roots {
                for cert in rustls_native_certs::load_native_certs().certs {
                    roots.add(cert).ok();
                }
            }
            let mut extra = self.extra_roots_der;
            for pem in &self.extra_roots_pem {
                extra.extend(pem_certs(pem, "PEM root")?);
            }
            for cert in extra {
                roots
                    .add(cert)
                    .map_err(|e| BoltError::Tls(format!("unusable root certificate: {e}")))?;
            }
            versions.with_root_certificates(roots)
        };

        let config = match self.identity {
            Some((cert_pem, key_pem)) => {
                let certs = pem_certs(&cert_pem, "client cert")?;
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

/// Every certificate in a PEM blob.
fn pem_certs(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut &*pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| BoltError::Tls(format!("invalid {what}: {e}")))
}

impl TlsProvider for RustlsProvider {
    fn connect<'a>(&'a self, server_name: &'a str, tcp: TcpStream) -> TlsHandshake<'a> {
        Box::pin(async move {
            let name = ServerName::try_from(server_name.to_string())
                .map_err(|e| BoltError::Tls(format!("invalid server name {server_name:?}: {e}")))?;
            let stream = self.connector.connect(name, tcp).await.map_err(|e| {
                // tokio-rustls reports TLS-level failures (untrusted cert,
                // bad name, no common cipher) as InvalidData; anything else
                // is the transport dropping mid-handshake, which is transient.
                if e.kind() == std::io::ErrorKind::InvalidData {
                    BoltError::Tls(format!("handshake with {server_name}: {e}"))
                } else {
                    BoltError::Io(e)
                }
            })?;
            Ok(Box::new(stream) as Box<dyn BoltStream>)
        })
    }
}

#[derive(Debug)]
enum Trust {
    /// Any certificate (`danger_accept_invalid_certs`).
    Any,
    /// Exactly these end-entity certificates.
    Pinned(Vec<CertificateDer<'static>>),
}

/// Certificate acceptance by [`Trust`] instead of chain verification. The
/// handshake signatures are still checked against the presented cert.
#[derive(Debug)]
struct CustomVerifier {
    trust: Trust,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for CustomVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        match &self.trust {
            Trust::Any => Ok(ServerCertVerified::assertion()),
            Trust::Pinned(pins) if pins.iter().any(|pin| pin.as_ref() == end_entity.as_ref()) => {
                Ok(ServerCertVerified::assertion())
            }
            Trust::Pinned(_) => Err(tokio_rustls::rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
        }
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
