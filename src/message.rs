//! Bolt message signatures, request builders, response decoding.

use crate::value::BoltValue;
use std::collections::HashMap;

// Client -> server request signatures.
pub const HELLO: u8 = 0x01;
pub const GOODBYE: u8 = 0x02;
pub const RESET: u8 = 0x0F;
pub const RUN: u8 = 0x10;
pub const BEGIN: u8 = 0x11;
pub const COMMIT: u8 = 0x12;
pub const ROLLBACK: u8 = 0x13;
pub const DISCARD: u8 = 0x2F;
pub const PULL: u8 = 0x3F;
pub const ROUTE: u8 = 0x66;
pub const LOGON: u8 = 0x6A;
pub const LOGOFF: u8 = 0x6B;

// Server -> client response signatures.
pub const SUCCESS: u8 = 0x70;
pub const RECORD: u8 = 0x71;
pub const IGNORED: u8 = 0x7E;
pub const FAILURE: u8 = 0x7F;

/// A request message ready to be framed and written.
#[derive(Debug, Clone)]
pub struct Request {
    pub signature: u8,
    pub fields: Vec<BoltValue>,
}

impl Request {
    #[must_use]
    pub fn new(signature: u8, fields: Vec<BoltValue>) -> Self {
        Self { signature, fields }
    }

    /// A message whose single field is a metadata map (HELLO, LOGON, PULL, ...).
    #[must_use]
    fn with_meta(signature: u8, meta: HashMap<String, BoltValue>) -> Self {
        Self::new(signature, vec![BoltValue::Map(meta)])
    }

    /// HELLO (Bolt 5.1+): metadata only, auth goes in LOGON.
    /// `bolt_agent` is mandatory for Neo4j 5.x.
    #[must_use]
    pub fn hello(user_agent: &str) -> Self {
        let lang = format!("Rust/{}", option_env!("CARGO_PKG_RUST_VERSION").unwrap_or("stable"));
        let bolt_agent = string_map([("product", user_agent), ("language", &lang)]);

        let mut meta = HashMap::new();
        meta.insert("user_agent".to_string(), BoltValue::String(user_agent.to_string()));
        meta.insert("bolt_agent".to_string(), BoltValue::Map(bolt_agent));
        Self::with_meta(HELLO, meta)
    }

    /// LOGON with basic auth.
    #[must_use]
    pub fn logon_basic(principal: &str, credentials: &str) -> Self {
        Self::with_meta(
            LOGON,
            string_map([
                ("scheme", "basic"),
                ("principal", principal),
                ("credentials", credentials),
            ]),
        )
    }

    /// LOGON with no credentials. Bolt 5.1+ sessions sit in AUTHENTICATION
    /// state after HELLO; auth-less servers still require this to go READY.
    #[must_use]
    pub fn logon_none() -> Self {
        Self::with_meta(LOGON, string_map([("scheme", "none")]))
    }

    /// RUN an auto-commit query: `[query, parameters, extra]`.
    #[must_use]
    pub fn run(
        query: &str,
        parameters: HashMap<String, BoltValue>,
        extra: HashMap<String, BoltValue>,
    ) -> Self {
        Self::new(
            RUN,
            vec![
                BoltValue::String(query.to_string()),
                BoltValue::Map(parameters),
                BoltValue::Map(extra),
            ],
        )
    }

    /// PULL `n` records (`n = -1` means "all") from stream `qid`
    /// (`None` targets the last-opened stream).
    #[must_use]
    pub fn pull(n: i64, qid: Option<i64>) -> Self {
        Self::with_n(PULL, n, qid)
    }

    /// DISCARD `n` records (`n = -1` means "all remaining").
    #[must_use]
    pub fn discard(n: i64, qid: Option<i64>) -> Self {
        Self::with_n(DISCARD, n, qid)
    }

    fn with_n(signature: u8, n: i64, qid: Option<i64>) -> Self {
        let mut meta = HashMap::new();
        meta.insert("n".to_string(), BoltValue::Int(n));
        if let Some(qid) = qid {
            meta.insert("qid".to_string(), BoltValue::Int(qid));
        }
        Self::with_meta(signature, meta)
    }

    /// BEGIN an explicit transaction. `extra`: mode/db/`tx_timeout`/`tx_metadata`/bookmarks.
    #[must_use]
    pub fn begin(extra: HashMap<String, BoltValue>) -> Self {
        Self::with_meta(BEGIN, extra)
    }

    /// ROUTE (Bolt 5.x): `[routing_context, bookmarks, extra{db?}]`.
    #[must_use]
    pub fn route(context: HashMap<String, BoltValue>, db: Option<&str>) -> Self {
        let mut extra = HashMap::new();
        if let Some(db) = db {
            extra.insert("db".to_string(), BoltValue::String(db.to_string()));
        }
        Self::new(
            ROUTE,
            vec![BoltValue::Map(context), BoltValue::List(vec![]), BoltValue::Map(extra)],
        )
    }

    empty_msg!(commit => COMMIT, rollback => ROLLBACK, reset => RESET, goodbye => GOODBYE);
}

/// Constructors for messages that carry no fields.
macro_rules! empty_msg {
    ($($name:ident => $sig:ident),+ $(,)?) => {
        $(#[must_use]
        pub fn $name() -> Self {
            Self::new($sig, vec![])
        })+
    };
}
use empty_msg;

/// A decoded server response.
#[derive(Debug, Clone)]
pub enum Response {
    /// SUCCESS carries a metadata map (fields list, bookmarks, stats, ...).
    Success(HashMap<String, BoltValue>),
    /// RECORD carries one row's values.
    Record(Vec<BoltValue>),
    /// FAILURE carries `code` and `message`.
    Failure { code: String, message: String },
    /// IGNORED - the server skipped this request (usually after a FAILURE).
    Ignored,
}

impl Response {
    /// Interpret a decoded top-level `Structure` as a server response.
    #[must_use]
    pub fn from_structure(signature: u8, mut fields: Vec<BoltValue>) -> Option<Self> {
        match signature {
            SUCCESS => Some(Response::Success(take_map(fields.pop()))),
            RECORD => match fields.pop() {
                Some(BoltValue::List(values)) => Some(Response::Record(values)),
                _ => Some(Response::Record(vec![])),
            },
            IGNORED => Some(Response::Ignored),
            FAILURE => {
                let meta = take_map(fields.pop());
                let get = |key, default: &str| {
                    meta.get(key).and_then(BoltValue::as_str).unwrap_or(default).to_string()
                };
                Some(Response::Failure {
                    code: get("code", "Unknown"),
                    message: get("message", "(no message)"),
                })
            }
            _ => None,
        }
    }
}

fn take_map(field: Option<BoltValue>) -> HashMap<String, BoltValue> {
    match field {
        Some(BoltValue::Map(m)) => m,
        _ => HashMap::new(),
    }
}

/// Build a string-to-string metadata map.
fn string_map<const N: usize>(pairs: [(&str, &str); N]) -> HashMap<String, BoltValue> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), BoltValue::String(v.to_string()))).collect()
}
