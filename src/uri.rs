//! URI-driven configuration: `bolt://user:pass@host:7687?db=name` and the
//! `+s` (strict TLS) / `+ssc` (accept self-signed) / `neo4j` (routed) schemes.

use crate::connection::{Auth, BoltConnection};
use crate::error::{BoltError, Result};
use crate::routed::RoutedPool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Bolt,
    BoltS,
    BoltSsc,
    Neo4j,
    Neo4jS,
    Neo4jSsc,
}

impl Scheme {
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "bolt" => Self::Bolt,
            "bolt+s" => Self::BoltS,
            "bolt+ssc" => Self::BoltSsc,
            "neo4j" => Self::Neo4j,
            "neo4j+s" => Self::Neo4jS,
            "neo4j+ssc" => Self::Neo4jSsc,
            other => return Err(BoltError::Protocol(format!("unknown URI scheme: {other}"))),
        })
    }

    #[must_use]
    pub fn routed(self) -> bool {
        matches!(self, Self::Neo4j | Self::Neo4jS | Self::Neo4jSsc)
    }

    fn tls(self) -> Tls {
        match self {
            Self::Bolt | Self::Neo4j => Tls::Off,
            Self::BoltS | Self::Neo4jS => Tls::Strict,
            Self::BoltSsc | Self::Neo4jSsc => Tls::AcceptInvalid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tls {
    Off,
    Strict,
    AcceptInvalid,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub auth: Option<Auth>,
    pub db: Option<String>,
}

impl Config {
    /// Parse `scheme://[user:pass@]host[:port][?db=name]`.
    /// No percent-decoding; keep credentials URL-safe.
    pub fn from_uri(uri: &str) -> Result<Self> {
        let err = |m: &str| BoltError::Protocol(format!("invalid URI: {m}"));

        let (scheme, rest) = uri.split_once("://").ok_or_else(|| err("missing ://"))?;
        let scheme = Scheme::parse(scheme)?;

        let (rest, query) = match rest.split_once('?') {
            Some((r, q)) => (r, Some(q)),
            None => (rest, None),
        };

        let (auth, hostport) = match rest.rsplit_once('@') {
            Some((userinfo, hp)) => {
                let (user, pass) =
                    userinfo.split_once(':').ok_or_else(|| err("userinfo needs user:pass"))?;
                (Some(Auth::basic(user, pass)), hp)
            }
            None => (None, rest),
        };

        // `[::1]:7687` style IPv6 first, then plain host[:port].
        let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
            let (h, after) = rest.split_once(']').ok_or_else(|| err("unclosed IPv6 bracket"))?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse::<u16>().map_err(|_| err("bad port"))?,
                None if after.is_empty() => 7687,
                None => return Err(err("junk after IPv6 host")),
            };
            (h, port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h, p.parse::<u16>().map_err(|_| err("bad port"))?),
                None => (hostport, 7687),
            }
        };
        if host.is_empty() {
            return Err(err("empty host"));
        }

        let db = query.and_then(|q| {
            q.split('&').find_map(|kv| kv.strip_prefix("db=").map(ToString::to_string))
        });

        Ok(Self { scheme, host: host.to_string(), port, auth, db })
    }

    #[must_use]
    pub fn addr(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Direct connection (`bolt`/`bolt+s`/`bolt+ssc`). `neo4j*` schemes are
    /// routed; use [`routed_pool`](Self::routed_pool).
    pub async fn connect(&self) -> Result<BoltConnection> {
        if self.scheme.routed() {
            return Err(BoltError::Protocol(
                "neo4j:// schemes are routed; use Config::routed_pool".into(),
            ));
        }
        dial(self.scheme.tls(), &self.addr(), &self.host, self.auth.clone()).await
    }

    /// Routed pool over the cluster behind a `neo4j*` URI (a `bolt*` URI just
    /// degenerates to its single host).
    #[must_use]
    pub fn routed_pool(&self, max_per_host: usize) -> RoutedPool {
        let tls = self.scheme.tls();
        let auth = self.auth.clone();
        RoutedPool::new(vec![self.addr()], self.db.clone(), max_per_host, move |server| {
            let auth = auth.clone();
            async move {
                let host = server.rsplit_once(':').map_or(server.as_str(), |(h, _)| h).to_string();
                dial(tls, &server, &host, auth).await
            }
        })
    }
}

async fn dial(tls: Tls, addr: &str, host: &str, auth: Option<Auth>) -> Result<BoltConnection> {
    match tls {
        Tls::Off => BoltConnection::connect(addr, auth).await,
        #[cfg(feature = "tls-rustls")]
        Tls::Strict | Tls::AcceptInvalid => {
            let builder = crate::tls::rustls::RustlsProvider::builder();
            let provider = if tls == Tls::AcceptInvalid {
                builder.danger_accept_invalid_certs(true)
            } else {
                builder.use_native_roots()
            }
            .build()?;
            BoltConnection::connect_tls(addr, host, auth, &provider).await
        }
        #[cfg(not(feature = "tls-rustls"))]
        Tls::Strict | Tls::AcceptInvalid => {
            let _ = (addr, host);
            Err(BoltError::Protocol("TLS scheme requires the tls-rustls feature".into()))
        }
    }
}

#[cfg(test)]
mod test;
