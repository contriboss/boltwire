//! Scripted loopback Bolt 5.8 server, just capable enough to drive boltwire
//! without a database. Shared by the integration tests via `#[path]`.
//!
//! Behaviour is picked per query by a prefix in the RUN text:
//!
//! - `slow:<ms>:...`     delay the RUN reply by `<ms>`
//! - `split:<ms>:...`    send the RECORD in two halves, `<ms>` apart
//! - `fail:...`          answer RUN with FAILURE
//! - `pullfail:...`      RUN succeeds, PULL fails
//! - `pipe:...`          withhold the RUN reply until the PULL has arrived
//! - `rows:<n>:...`      stream `<n>` rows (honouring PULL's `n`)
//! - anything else       one column `q`, one row holding the query text
//!
//! BEGIN fails when its `db` is `"fail"`. ROUTE answers with this server in
//! every role.
//!
//! Every row carries the query text, so a test can tell whose result it got.
//! A FAILURE puts the session in FAILED: everything but RESET is IGNORED.

#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boltwire::BoltValue;
use boltwire::message::{
    BEGIN, COMMIT, DISCARD, FAILURE, GOODBYE, HELLO, IGNORED, LOGON, PULL, RECORD, RESET, ROLLBACK,
    ROUTE, RUN, SUCCESS,
};
use boltwire::packstream::{Reader, pack};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

/// Server-wide knobs (per-query behaviour comes from the RUN prefix).
#[derive(Clone, Default)]
pub struct Options {
    /// Answer LOGON with this `(code, message)` FAILURE, then hang up.
    pub logon_failure: Option<(String, String)>,
    /// After LOGON, stop reading for this long (lets the client's socket
    /// buffers fill so a large write blocks mid-frame).
    pub pause_after_logon: Option<Duration>,
    /// Speak TLS with this config before the Bolt handshake.
    #[cfg(feature = "tls-rustls")]
    pub tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

async fn accept(socket: TcpStream, options: &Options) -> Option<Box<dyn Io>> {
    #[cfg(feature = "tls-rustls")]
    if let Some(config) = &options.tls {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(config));
        return Some(Box::new(acceptor.accept(socket).await.ok()?));
    }
    let _ = options;
    Some(Box::new(socket))
}

pub struct FakeBolt {
    pub addr: SocketAddr,
    shared: Arc<Shared>,
}

#[derive(Default)]
struct Shared {
    accepted: AtomicUsize,
    closed: AtomicUsize,
    closed_notify: Notify,
    /// `(connection index, signature)` for every message received.
    log: Mutex<Vec<(usize, u8)>>,
}

impl FakeBolt {
    pub async fn start() -> Self {
        Self::start_with(Options::default()).await
    }

    pub async fn start_with(options: Options) -> Self {
        Self::bind("127.0.0.1:0", options)
            .await
            .expect("bind loopback")
    }

    /// Bind an arbitrary address (e.g. `[::1]:0`); `None` if unavailable.
    pub async fn bind(addr: &str, options: Options) -> Option<Self> {
        let listener = TcpListener::bind(addr).await.ok()?;
        let server = Self {
            addr: listener.local_addr().ok()?,
            shared: Arc::default(),
        };
        let shared = Arc::clone(&server.shared);
        let self_addr = server.addr.to_string();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                socket.set_nodelay(true).ok();
                let id = shared.accepted.fetch_add(1, Ordering::SeqCst);
                let (shared, options) = (Arc::clone(&shared), options.clone());
                let self_addr = self_addr.clone();
                tokio::spawn(async move {
                    if let Some(stream) = accept(socket, &options).await {
                        let mut session = Session::new(id, stream, options, Arc::clone(&shared));
                        session.self_addr = self_addr;
                        session.serve().await;
                    }
                    shared.closed.fetch_add(1, Ordering::SeqCst);
                    shared.closed_notify.notify_waiters();
                });
            }
        });
        Some(server)
    }

    pub fn addr(&self) -> String {
        self.addr.to_string()
    }

    /// Connections accepted so far.
    pub fn accepted(&self) -> usize {
        self.shared.accepted.load(Ordering::SeqCst)
    }

    /// Connections the server has seen end.
    pub fn closed(&self) -> usize {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// Wait until at least `n` connections have ended.
    pub async fn wait_closed(&self, n: usize) {
        loop {
            let notified = self.shared.closed_notify.notified();
            if self.closed() >= n {
                return;
            }
            notified.await;
        }
    }

    /// Signatures received on connection `id`, in order.
    pub fn signatures(&self, id: usize) -> Vec<u8> {
        let log = self.shared.log.lock().expect("log");
        log.iter()
            .filter(|(c, _)| *c == id)
            .map(|(_, s)| *s)
            .collect()
    }
}

struct Session {
    id: usize,
    socket: Box<dyn Io>,
    options: Options,
    shared: Arc<Shared>,
    failed: bool,
    /// Rows of the open result stream, plus its query for PULL scripting.
    stream: VecDeque<Vec<BoltValue>>,
    query: String,
    /// A message read ahead (by `pipe:`) and not yet handled.
    lookahead: Option<(u8, Vec<BoltValue>)>,
    /// This server's own address, as ROUTE advertises it.
    self_addr: String,
}

impl Session {
    fn new(id: usize, socket: Box<dyn Io>, options: Options, shared: Arc<Shared>) -> Self {
        Self {
            id,
            socket,
            options,
            shared,
            failed: false,
            stream: VecDeque::new(),
            query: String::new(),
            lookahead: None,
            self_addr: String::new(),
        }
    }

    async fn serve(mut self) {
        let mut hello = [0u8; 20];
        if self.socket.read_exact(&mut hello).await.is_err() {
            return;
        }
        if self.socket.write_all(&[0, 0, 8, 5]).await.is_err() {
            return;
        }
        loop {
            let msg = match self.lookahead.take() {
                Some(msg) => msg,
                None => match self.read().await {
                    Some(msg) => msg,
                    None => return,
                },
            };
            if self.handle(msg).await.is_err() {
                return;
            }
        }
    }

    async fn read(&mut self) -> Option<(u8, Vec<BoltValue>)> {
        let msg = read_message(&mut self.socket).await?;
        self.shared.log.lock().expect("log").push((self.id, msg.0));
        Some(msg)
    }

    async fn handle(&mut self, (signature, fields): (u8, Vec<BoltValue>)) -> Result<(), ()> {
        if signature == GOODBYE {
            return Err(());
        }
        if signature == RESET {
            self.failed = false;
            self.stream.clear();
            return self.send(SUCCESS, meta(&[])).await;
        }
        if self.failed {
            return self.send(IGNORED, vec![]).await;
        }
        match signature {
            HELLO => {
                let id = format!("fake-{}", self.id);
                self.send(
                    SUCCESS,
                    meta(&[
                        ("server", "FakeBolt/1.0".into()),
                        ("connection_id", id.into()),
                    ]),
                )
                .await
            }
            LOGON => {
                if let Some((code, message)) = self.options.logon_failure.clone() {
                    self.send(failure(&code, &message).0, failure(&code, &message).1)
                        .await?;
                    return Err(());
                }
                self.send(SUCCESS, meta(&[])).await?;
                if let Some(pause) = self.options.pause_after_logon {
                    tokio::time::sleep(pause).await;
                }
                Ok(())
            }
            RUN => self.run(&fields).await,
            PULL => self.pull(&fields).await,
            DISCARD => {
                self.stream.clear();
                self.send(SUCCESS, meta(&[("has_more", false.into())]))
                    .await
            }
            COMMIT => {
                self.send(SUCCESS, meta(&[("bookmark", "bm:1".into())]))
                    .await
            }
            BEGIN if db(&fields) == Some("fail") => {
                self.fail("Fake.ClientError.Database.DatabaseNotFound", "no such db")
                    .await
            }
            BEGIN | ROLLBACK => self.send(SUCCESS, meta(&[])).await,
            ROUTE => {
                let me = BoltValue::List(vec![self.self_addr.clone().into()]);
                let servers = ["ROUTE", "READ", "WRITE"]
                    .into_iter()
                    .map(|role| map(&[("addresses", me.clone()), ("role", role.into())]))
                    .collect();
                let rt = map(&[
                    ("ttl", BoltValue::Int(300)),
                    ("servers", BoltValue::List(servers)),
                ]);
                self.send(SUCCESS, meta(&[("rt", rt)])).await
            }
            _ => {
                self.fail("Fake.ClientError.Request.Invalid", "unknown message")
                    .await
            }
        }
    }

    async fn run(&mut self, fields: &[BoltValue]) -> Result<(), ()> {
        let query = fields
            .first()
            .and_then(BoltValue::as_str)
            .unwrap_or_default()
            .to_string();
        let (verb, arg) = prefix(&query);
        match verb.as_str() {
            "slow" => tokio::time::sleep(Duration::from_millis(arg)).await,
            "fail" => {
                return self
                    .fail("Fake.ClientError.Statement.SyntaxError", "boom")
                    .await;
            }
            "pipe" => {
                // A client that waits for this reply before sending PULL
                // deadlocks here, which is the point.
                let next = self.read().await.ok_or(())?;
                self.lookahead = Some(next);
            }
            _ => {}
        }
        let rows = if verb == "rows" { arg } else { 1 };
        self.stream = (0..rows)
            .map(|i| {
                let i = i64::try_from(i).unwrap_or(i64::MAX);
                vec![BoltValue::from(query.clone()), BoltValue::Int(i)]
            })
            .collect();
        if verb != "rows" {
            for row in &mut self.stream {
                row.truncate(1);
            }
        }
        self.query = query;
        let columns: Vec<BoltValue> = if verb == "rows" {
            vec!["q".into(), "i".into()]
        } else {
            vec!["q".into()]
        };
        self.send(SUCCESS, meta(&[("fields", BoltValue::List(columns))]))
            .await
    }

    async fn pull(&mut self, fields: &[BoltValue]) -> Result<(), ()> {
        let n = match fields.first() {
            Some(BoltValue::Map(m)) => m.get("n").and_then(BoltValue::as_int).unwrap_or(-1),
            _ => -1,
        };
        let (verb, arg) = prefix(&self.query);
        if verb == "pullfail" {
            return self
                .fail("Fake.DatabaseError.General.Boom", "pull boom")
                .await;
        }
        let take = if n < 0 {
            self.stream.len()
        } else {
            usize::try_from(n)
                .unwrap_or(usize::MAX)
                .min(self.stream.len())
        };
        let rows: Vec<_> = self.stream.drain(..take).collect();
        for row in rows {
            if verb == "split" {
                self.send_split(RECORD, vec![BoltValue::List(row)], arg)
                    .await?;
            } else {
                self.send(RECORD, vec![BoltValue::List(row)]).await?;
            }
        }
        let has_more = !self.stream.is_empty();
        self.send(SUCCESS, meta(&[("has_more", has_more.into())]))
            .await
    }

    async fn fail(&mut self, code: &str, message: &str) -> Result<(), ()> {
        self.failed = true;
        self.stream.clear();
        let (sig, fields) = failure(code, message);
        self.send(sig, fields).await
    }

    async fn send(&mut self, signature: u8, fields: Vec<BoltValue>) -> Result<(), ()> {
        let frame = frame(signature, fields);
        self.socket.write_all(&frame).await.map_err(|_| ())
    }

    /// Write one message in two halves with a pause in between, so a client
    /// can be cancelled while holding half a message.
    async fn send_split(
        &mut self,
        signature: u8,
        fields: Vec<BoltValue>,
        pause_ms: u64,
    ) -> Result<(), ()> {
        let frame = frame(signature, fields);
        let mid = frame.len() / 2;
        self.socket.write_all(&frame[..mid]).await.map_err(|_| ())?;
        self.socket.flush().await.map_err(|_| ())?;
        tokio::time::sleep(Duration::from_millis(pause_ms)).await;
        self.socket.write_all(&frame[mid..]).await.map_err(|_| ())
    }
}

/// The `db` entry of a BEGIN's metadata map.
fn db(fields: &[BoltValue]) -> Option<&str> {
    fields.first()?.get("db")?.as_str()
}

/// `"slow:200:x"` -> `("slow", 200)`; `"fail:x"` -> `("fail", 0)`.
fn prefix(query: &str) -> (String, u64) {
    let mut parts = query.splitn(3, ':');
    let verb = parts.next().unwrap_or_default().to_string();
    let arg = parts.next().and_then(|a| a.parse().ok()).unwrap_or(0);
    (verb, arg)
}

fn failure(code: &str, message: &str) -> (u8, Vec<BoltValue>) {
    (
        FAILURE,
        meta(&[
            ("code", code.to_string().into()),
            ("message", message.to_string().into()),
        ]),
    )
}

/// A single-map field list, the shape of every summary message.
pub fn meta(entries: &[(&str, BoltValue)]) -> Vec<BoltValue> {
    vec![map(entries)]
}

pub fn map(entries: &[(&str, BoltValue)]) -> BoltValue {
    let map: HashMap<String, BoltValue> = entries
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect();
    BoltValue::Map(map)
}

/// Chunk a message (max 65535 bytes per chunk) and terminate it.
pub fn frame(signature: u8, fields: Vec<BoltValue>) -> Vec<u8> {
    let mut body = Vec::new();
    pack(&BoltValue::Structure { signature, fields }, &mut body).expect("pack");
    let mut out = Vec::with_capacity(body.len() + 4);
    for chunk in body.chunks(65_535) {
        let len = u16::try_from(chunk.len()).expect("chunk fits u16");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&[0, 0]);
    out
}

async fn read_message(socket: &mut (impl AsyncRead + Unpin)) -> Option<(u8, Vec<BoltValue>)> {
    let mut body = Vec::new();
    loop {
        let mut header = [0u8; 2];
        socket.read_exact(&mut header).await.ok()?;
        let size = usize::from(u16::from_be_bytes(header));
        if size == 0 {
            if body.is_empty() {
                continue;
            }
            break;
        }
        let start = body.len();
        body.resize(start + size, 0);
        socket.read_exact(&mut body[start..]).await.ok()?;
    }
    match Reader::new(&body).unpack().ok()? {
        BoltValue::Structure { signature, fields } => Some((signature, fields)),
        _ => None,
    }
}
