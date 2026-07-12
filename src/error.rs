//! Error types for the Bolt driver.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BoltError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The wire bytes didn't match what PackStream/Bolt expects.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// The connection closed or was lost mid-exchange.
    #[error("connection closed: {0}")]
    Closed(String),

    /// No mutually supported Bolt version. `agreed` is the server's reply.
    #[error("version negotiation failed: server agreed on {agreed}, client supports {supported}")]
    Version { agreed: String, supported: String },

    /// The server returned a FAILURE message (auth error, bad Cypher, ...).
    #[error("server failure [{code}]: {message}")]
    Failure { code: String, message: String },

    /// TLS setup or handshake failed (bad server name, untrusted certificate, ...).
    #[cfg(feature = "tls")]
    #[error("tls error: {0}")]
    Tls(String),

    /// An IO deadline expired.
    #[error("timed out: {0}")]
    Timeout(&'static str),
}

pub type Result<T> = std::result::Result<T, BoltError>;
