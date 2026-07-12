//! Swappable TLS seam. Backends live in feature-gated submodules.

use std::future::Future;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::error::Result;

#[cfg(feature = "tls-rustls")]
pub mod rustls;

pub trait BoltStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> BoltStream for T {}

pub type TlsHandshake<'a> = Pin<Box<dyn Future<Output = Result<Box<dyn BoltStream>>> + Send + 'a>>;

/// Boxed future, not `async fn`: keeps the trait dyn-safe.
pub trait TlsProvider: Send + Sync {
    /// Handshake over `tcp`; `server_name` is used for SNI + cert verification.
    fn connect<'a>(&'a self, server_name: &'a str, tcp: TcpStream) -> TlsHandshake<'a>;
}
