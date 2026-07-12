//! boltwire - pure-Rust async Bolt driver for Neo4j and Memgraph.
//!
//! ```no_run
//! use boltwire::{Auth, BoltConnection};
//! use std::collections::HashMap;
//!
//! # async fn demo() -> boltwire::Result<()> {
//! let mut conn = BoltConnection::connect(
//!     "127.0.0.1:7687",
//!     Some(Auth::basic("memgraph", "password")),
//! )
//! .await?;
//!
//! let result = conn.run("RETURN 1 AS n", HashMap::new()).await?;
//! assert_eq!(result.columns, vec!["n".to_string()]);
//! conn.close().await?;
//! # Ok(())
//! # }
//! ```

#![allow(clippy::implicit_hasher, clippy::missing_errors_doc)]

#[cfg(feature = "tracing")]
macro_rules! bolt_debug {
    ($($tt:tt)*) => { tracing::debug!(target: "boltwire", $($tt)*) };
}
#[cfg(not(feature = "tracing"))]
macro_rules! bolt_debug {
    ($($tt:tt)*) => {};
}

pub mod connection;
#[cfg(feature = "serde")]
pub mod convert;
pub mod error;
pub mod handshake;
pub mod message;
pub mod packstream;
pub mod pool;
pub mod routed;
pub mod routing;
#[cfg(feature = "tls")]
pub mod tls;
pub mod uri;
pub mod value;
pub mod view;

pub use connection::{Auth, BoltConnection, QueryResult, RecordStream, Transaction, TxOptions};
#[cfg(feature = "serde")]
pub use convert::{from_value, params, to_value};
pub use error::{BoltError, Result};
pub use handshake::Version;
pub use pool::{Pool, PoolConfig, PooledConnection};
pub use routed::{AccessMode, RoutedPool};
pub use routing::RoutingTable;
#[cfg(feature = "tls")]
pub use tls::{BoltStream, TlsProvider};
pub use uri::{Config, Scheme};
pub use value::BoltValue;
pub use view::{DurationRef, NodeRef, PathRef, PointRef, RelationshipRef, UnboundRelationshipRef};

#[cfg(feature = "tls-rustls")]
pub use tls::rustls::RustlsProvider;
