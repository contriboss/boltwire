//! Async Bolt connection: handshake, auth, queries, transactions, streaming.

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, ToSocketAddrs};

use crate::error::{BoltError, Result};
use crate::handshake::{self, Version};
use crate::message::{Request, Response};
use crate::packstream::{self, Reader};
use crate::routing::RoutingTable;
#[cfg(feature = "tls")]
use crate::tls::{BoltStream, TlsProvider};
use crate::value::BoltValue;

const MAX_CHUNK: usize = 65_535;
/// Upper bound on a single reassembled message; a server streaming past this
/// is broken or hostile.
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// Whole connect sequence: dial + handshake + HELLO + LOGON.
pub const DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Per-read deadline; NOOP keep-alives refresh it.
pub const DEFAULT_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

enum Stream {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<dyn BoltStream>),
    #[cfg(test)]
    Mem(tokio::io::DuplexStream),
}

/// Delegate a poll method to whichever transport is live.
macro_rules! delegate {
    ($self:ident, $method:ident, $($arg:expr),*) => {
        match $self.get_mut() {
            Stream::Plain(s) => Pin::new(s).$method($($arg),*),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => Pin::new(s.as_mut()).$method($($arg),*),
            #[cfg(test)]
            Stream::Mem(s) => Pin::new(s).$method($($arg),*),
        }
    };
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        delegate!(self, poll_read, cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        delegate!(self, poll_write, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        delegate!(self, poll_flush, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        delegate!(self, poll_shutdown, cx)
    }
}

/// Basic-auth credentials.
#[derive(Debug, Clone)]
pub struct Auth {
    pub principal: String,
    pub credentials: String,
}

impl Auth {
    #[must_use]
    pub fn basic(principal: impl Into<String>, credentials: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            credentials: credentials.into(),
        }
    }
}

/// Tabular result of a query.
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub records: Vec<Vec<BoltValue>>,
}

impl QueryResult {
    /// Zip each record's values with the column names into a map.
    #[must_use]
    pub fn rows_as_maps(&self) -> Vec<HashMap<String, BoltValue>> {
        self.records
            .iter()
            .map(|row| {
                self.columns
                    .iter()
                    .cloned()
                    .zip(row.iter().cloned())
                    .collect()
            })
            .collect()
    }
}

/// One Bolt session per socket. Single-plex: one query at a time.
pub struct BoltConnection {
    stream: Stream,
    version: Version,
    server_agent: Option<String>,
    connection_id: Option<String>,
    /// Set when a Transaction was dropped without commit/rollback; the next
    /// operation sends RESET first (which aborts the abandoned tx).
    needs_reset: bool,
    read_timeout: std::time::Duration,
}

impl BoltConnection {
    /// Plain TCP: dial, negotiate, HELLO, LOGON if `auth` given.
    pub async fn connect(addr: impl ToSocketAddrs, auth: Option<Auth>) -> Result<Self> {
        tokio::time::timeout(DEFAULT_CONNECT_TIMEOUT, async {
            let tcp = TcpStream::connect(addr).await?;
            tcp.set_nodelay(true).ok();
            Self::establish(Stream::Plain(tcp), auth).await
        })
        .await
        .map_err(|_| BoltError::Timeout("connect"))?
    }

    /// TLS: dial `addr`, handshake for `server_name` (SNI + cert check, may
    /// differ from dial addr), then the same Bolt exchange.
    #[cfg(feature = "tls")]
    pub async fn connect_tls(
        addr: impl ToSocketAddrs,
        server_name: &str,
        auth: Option<Auth>,
        tls: &dyn TlsProvider,
    ) -> Result<Self> {
        tokio::time::timeout(DEFAULT_CONNECT_TIMEOUT, async {
            let tcp = TcpStream::connect(addr).await?;
            tcp.set_nodelay(true).ok();
            let stream = tls.connect(server_name, tcp).await?;
            Self::establish(Stream::Tls(stream), auth).await
        })
        .await
        .map_err(|_| BoltError::Timeout("connect"))?
    }

    /// Per-read deadline (default [`DEFAULT_READ_TIMEOUT`]).
    pub fn set_read_timeout(&mut self, timeout: std::time::Duration) {
        self.read_timeout = timeout;
    }

    async fn establish(stream: Stream, auth: Option<Auth>) -> Result<Self> {
        let mut conn = Self {
            stream,
            version: Version::new(0, 0),
            server_agent: None,
            connection_id: None,
            needs_reset: false,
            read_timeout: DEFAULT_READ_TIMEOUT,
        };
        conn.handshake().await?;
        conn.hello().await?;
        // Bolt 5.1+ requires LOGON to leave AUTHENTICATION state, creds or not.
        let logon = match &auth {
            Some(a) => Request::logon_basic(&a.principal, &a.credentials),
            None => Request::logon_none(),
        };
        conn.write_message(&logon).await?;
        expect_success(conn.read_message().await?, "LOGON")?;
        bolt_debug!(
            version = %conn.version,
            server = conn.server_agent.as_deref().unwrap_or("?"),
            "session ready"
        );
        Ok(conn)
    }

    /// RESET if a prior transaction was abandoned (dropped mid-flight).
    async fn ensure_clean(&mut self) -> Result<()> {
        if self.needs_reset {
            self.reset().await?;
            self.needs_reset = false;
        }
        Ok(())
    }

    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    #[must_use]
    pub fn server_agent(&self) -> Option<&str> {
        self.server_agent.as_deref()
    }

    #[must_use]
    pub fn connection_id(&self) -> Option<&str> {
        self.connection_id.as_deref()
    }

    async fn handshake(&mut self) -> Result<()> {
        self.stream.write_all(&handshake::client_hello()).await?;
        self.stream.flush().await?;

        let mut agreed = [0u8; 4];
        self.read_exact_timed(&mut agreed).await?;
        let version = Version::decode(agreed);

        if version.is_zero() || !handshake::supported(version) {
            return Err(BoltError::Version {
                agreed: version.to_string(),
                supported: handshake::SUPPORTED_RANGE.to_string(),
            });
        }
        self.version = version;
        Ok(())
    }

    async fn hello(&mut self) -> Result<()> {
        let agent = format!("boltwire/{} (Rust)", env!("CARGO_PKG_VERSION"));
        self.write_message(&Request::hello(&agent)).await?;
        let meta = expect_success(self.read_message().await?, "HELLO")?;
        self.server_agent = meta_str(&meta, "server");
        self.connection_id = meta_str(&meta, "connection_id");
        Ok(())
    }

    /// RESET out of the post-FAILURE discarding state, then surface the error.
    async fn fail_reset(&mut self, code: String, message: String) -> BoltError {
        self.reset().await.ok();
        BoltError::Failure { code, message }
    }

    /// Run an auto-commit query and drain all records.
    pub async fn run(
        &mut self,
        query: &str,
        parameters: HashMap<String, BoltValue>,
    ) -> Result<QueryResult> {
        self.run_with(query, parameters, HashMap::new()).await
    }

    /// Like [`run`](Self::run) with an explicit `extra` map (`db`, `mode: "r"`,
    /// `tx_timeout`, `bookmarks`, ...).
    pub async fn run_with(
        &mut self,
        query: &str,
        parameters: HashMap<String, BoltValue>,
        extra: HashMap<String, BoltValue>,
    ) -> Result<QueryResult> {
        self.ensure_clean().await?;
        self.run_inner(query, parameters, extra).await
    }

    /// Send RUN, await SUCCESS, return the column names and stream `qid`
    /// (servers only assign qids inside explicit transactions).
    async fn send_run(
        &mut self,
        query: &str,
        parameters: HashMap<String, BoltValue>,
        extra: HashMap<String, BoltValue>,
    ) -> Result<(Vec<String>, Option<i64>)> {
        self.write_message(&Request::run(query, parameters, extra))
            .await?;
        match self.read_message().await? {
            Response::Success(meta) => {
                let qid = meta.get("qid").and_then(BoltValue::as_int);
                Ok((extract_columns(&meta), qid))
            }
            Response::Failure { code, message } => Err(self.fail_reset(code, message).await),
            other => Err(BoltError::Protocol(format!(
                "unexpected RUN response: {other:?}"
            ))),
        }
    }

    /// RUN + PULL, no state checks. Shared by autocommit and explicit tx.
    async fn run_inner(
        &mut self,
        query: &str,
        parameters: HashMap<String, BoltValue>,
        extra: HashMap<String, BoltValue>,
    ) -> Result<QueryResult> {
        bolt_debug!(query, "run");
        let (columns, qid) = self.send_run(query, parameters, extra).await?;

        self.write_message(&Request::pull(-1, qid)).await?;
        let mut records = Vec::new();
        loop {
            match self.read_message().await? {
                Response::Record(values) => records.push(values),
                Response::Success(_) => break,
                Response::Failure { code, message } => {
                    return Err(self.fail_reset(code, message).await);
                }
                Response::Ignored => {
                    return Err(BoltError::Protocol("PULL ignored by server".into()));
                }
            }
        }
        Ok(QueryResult { columns, records })
    }

    /// RUN with batched PULLs: constant memory, records arrive per batch.
    pub async fn run_stream(
        &mut self,
        query: &str,
        parameters: HashMap<String, BoltValue>,
        batch: i64,
    ) -> Result<RecordStream<'_>> {
        self.run_stream_with(query, parameters, HashMap::new(), batch)
            .await
    }

    /// [`run_stream`](Self::run_stream) with an explicit `extra` map.
    pub async fn run_stream_with(
        &mut self,
        query: &str,
        parameters: HashMap<String, BoltValue>,
        extra: HashMap<String, BoltValue>,
        batch: i64,
    ) -> Result<RecordStream<'_>> {
        validate_batch(batch)?;
        self.ensure_clean().await?;
        let (columns, qid) = self.send_run(query, parameters, extra).await?;
        Ok(RecordStream {
            conn: self,
            columns,
            qid,
            batch,
            buffer: VecDeque::new(),
            has_more: true,
            done: false,
            summary: None,
        })
    }

    /// BEGIN an explicit transaction with default options.
    pub async fn begin(&mut self) -> Result<Transaction<'_>> {
        self.begin_with(TxOptions::default()).await
    }

    /// BEGIN with options. The transaction borrows the connection; dropping it
    /// without commit/rollback aborts it (RESET) on the next operation.
    pub async fn begin_with(&mut self, opts: TxOptions) -> Result<Transaction<'_>> {
        self.ensure_clean().await?;
        bolt_debug!("begin");
        self.write_message(&Request::begin(opts.into_meta()))
            .await?;
        expect_success(self.read_message().await?, "BEGIN")?;
        Ok(Transaction {
            conn: self,
            done: false,
        })
    }

    /// Fetch the routing table (ROUTE). Single instances hold every role;
    /// Memgraph returns a server failure.
    pub async fn route(
        &mut self,
        context: HashMap<String, BoltValue>,
        db: Option<&str>,
    ) -> Result<RoutingTable> {
        self.ensure_clean().await?;
        self.write_message(&Request::route(context, db)).await?;
        match self.read_message().await? {
            Response::Success(meta) => RoutingTable::from_meta(&meta),
            Response::Failure { code, message } => Err(self.fail_reset(code, message).await),
            other => Err(BoltError::Protocol(format!(
                "unexpected ROUTE response: {other:?}"
            ))),
        }
    }

    /// Send RESET and await SUCCESS. Clears failed state and aborts any open tx.
    pub async fn reset(&mut self) -> Result<()> {
        self.write_message(&Request::reset()).await?;
        loop {
            match self.read_message().await? {
                Response::Success(_) => {
                    self.needs_reset = false;
                    return Ok(());
                }
                Response::Ignored | Response::Record(_) => {}
                Response::Failure { code, message } => {
                    return Err(BoltError::Failure { code, message });
                }
            }
        }
    }

    /// Send GOODBYE and close the socket.
    pub async fn close(mut self) -> Result<()> {
        self.write_message(&Request::goodbye()).await?;
        self.stream.shutdown().await?;
        Ok(())
    }

    // ---- framing ----

    async fn write_message(&mut self, req: &Request) -> Result<()> {
        let mut body = Vec::new();
        // A message is itself a PackStream structure: signature + fields.
        packstream::pack(
            &BoltValue::Structure {
                signature: req.signature,
                fields: req.fields.clone(),
            },
            &mut body,
        )?;

        // Chunk the body (16-bit length-prefixed segments), then a zero terminator.
        for chunk in body.chunks(MAX_CHUNK) {
            let len = u16::try_from(chunk.len()).unwrap();
            self.stream.write_all(&len.to_be_bytes()).await?;
            self.stream.write_all(chunk).await?;
        }
        self.stream.write_all(&[0x00, 0x00]).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn read_exact_timed(&mut self, buf: &mut [u8]) -> Result<()> {
        tokio::time::timeout(self.read_timeout, self.stream.read_exact(buf))
            .await
            .map_err(|_| BoltError::Timeout("read"))?
            .map_err(map_eof)?;
        Ok(())
    }

    async fn read_message(&mut self) -> Result<Response> {
        let mut body = Vec::new();
        loop {
            let mut header = [0u8; 2];
            self.read_exact_timed(&mut header).await?;
            let size = usize::from(u16::from_be_bytes(header));
            if size == 0 {
                // 0x0000 with an empty body is a keep-alive NOOP, not a
                // message boundary; skip it.
                if body.is_empty() {
                    continue;
                }
                break;
            }
            let start = body.len();
            if start + size > MAX_MESSAGE {
                return Err(BoltError::Protocol("message exceeds 64MiB limit".into()));
            }
            body.resize(start + size, 0);
            let mut chunk = std::mem::take(&mut body);
            let read = self.read_exact_timed(&mut chunk[start..]).await;
            body = chunk;
            read?;
        }

        let value = Reader::new(&body).unpack()?;
        let BoltValue::Structure { signature, fields } = value else {
            return Err(BoltError::Protocol(
                "message body is not a structure".into(),
            ));
        };
        Response::from_structure(signature, fields).ok_or_else(|| {
            BoltError::Protocol(format!("unknown message signature 0x{signature:02x}"))
        })
    }
}

/// Options for [`BoltConnection::begin_with`].
#[derive(Debug, Clone, Default)]
pub struct TxOptions {
    /// Target database (Neo4j 4+). Memgraph rejects this key; leave unset there.
    pub db: Option<String>,
    /// Routes to a reader in a cluster; also lets the server reject writes.
    pub read_only: bool,
    pub timeout_ms: Option<i64>,
    /// Causal-consistency bookmarks this tx must observe.
    pub bookmarks: Vec<String>,
    pub metadata: HashMap<String, BoltValue>,
}

impl TxOptions {
    fn into_meta(self) -> HashMap<String, BoltValue> {
        let mut meta = HashMap::new();
        if let Some(db) = self.db {
            meta.insert("db".to_string(), BoltValue::from(db));
        }
        if self.read_only {
            meta.insert("mode".to_string(), BoltValue::from("r"));
        }
        if let Some(ms) = self.timeout_ms {
            meta.insert("tx_timeout".to_string(), BoltValue::Int(ms));
        }
        if !self.bookmarks.is_empty() {
            let list = self.bookmarks.into_iter().map(BoltValue::from).collect();
            meta.insert("bookmarks".to_string(), BoltValue::List(list));
        }
        if !self.metadata.is_empty() {
            meta.insert("tx_metadata".to_string(), BoltValue::Map(self.metadata));
        }
        meta
    }
}

/// Explicit transaction; end with `commit()`/`rollback()`, drop aborts via RESET.
pub struct Transaction<'c> {
    conn: &'c mut BoltConnection,
    done: bool,
}

impl Transaction<'_> {
    fn guard_open(&mut self) -> Result<()> {
        if self.conn.needs_reset {
            self.done = true;
            return Err(BoltError::Protocol(
                "stream abandoned mid-transaction; tx aborted".into(),
            ));
        }
        if self.done {
            return Err(BoltError::Protocol("transaction already closed".into()));
        }
        Ok(())
    }

    /// Run a statement inside the transaction. A server FAILURE aborts the tx
    /// (RESET is sent); further statements or commit then error client-side.
    pub async fn run(
        &mut self,
        query: &str,
        parameters: HashMap<String, BoltValue>,
    ) -> Result<QueryResult> {
        self.guard_open()?;
        let result = self.conn.run_inner(query, parameters, HashMap::new()).await;
        if result.is_err() {
            // fail_reset already RESET the server, which killed the tx.
            self.done = true;
        }
        result
    }

    /// Stream a statement's records inside the transaction, `batch` at a time.
    /// Drain or `finish()` the stream before the next statement or commit.
    pub async fn run_stream(
        &mut self,
        query: &str,
        parameters: HashMap<String, BoltValue>,
        batch: i64,
    ) -> Result<RecordStream<'_>> {
        validate_batch(batch)?;
        self.guard_open()?;
        let run = self.conn.send_run(query, parameters, HashMap::new()).await;
        let (columns, qid) = match run {
            Ok(ok) => ok,
            Err(e) => {
                self.done = true;
                return Err(e);
            }
        };
        Ok(RecordStream {
            conn: self.conn,
            columns,
            qid,
            batch,
            buffer: VecDeque::new(),
            has_more: true,
            done: false,
            summary: None,
        })
    }

    /// COMMIT. Returns the server bookmark, if any.
    pub async fn commit(mut self) -> Result<Option<String>> {
        self.guard_open()?;
        self.done = true;
        self.conn.write_message(&Request::commit()).await?;
        let meta = self.finish_end("COMMIT").await?;
        Ok(meta_str(&meta, "bookmark"))
    }

    /// ROLLBACK. No-op if the tx already died to a failed statement.
    pub async fn rollback(mut self) -> Result<()> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        self.conn.write_message(&Request::rollback()).await?;
        self.finish_end("ROLLBACK").await?;
        Ok(())
    }

    async fn finish_end(&mut self, ctx: &str) -> Result<HashMap<String, BoltValue>> {
        match self.conn.read_message().await? {
            Response::Success(meta) => Ok(meta),
            Response::Failure { code, message } => Err(self.conn.fail_reset(code, message).await),
            other => Err(BoltError::Protocol(format!(
                "unexpected {ctx} response: {other:?}"
            ))),
        }
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.conn.needs_reset = true;
        }
    }
}

/// Batched result stream: `PULL {n}` with `has_more` continuation.
/// `next()` consumes, `finish()` DISCARDs the rest; drop recovers via RESET.
pub struct RecordStream<'c> {
    conn: &'c mut BoltConnection,
    columns: Vec<String>,
    qid: Option<i64>,
    batch: i64,
    buffer: VecDeque<Vec<BoltValue>>,
    has_more: bool,
    done: bool,
    summary: Option<HashMap<String, BoltValue>>,
}

impl RecordStream<'_> {
    #[must_use]
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// Next record, fetching the next batch when the buffer runs dry.
    pub async fn next(&mut self) -> Result<Option<Vec<BoltValue>>> {
        loop {
            if let Some(row) = self.buffer.pop_front() {
                return Ok(Some(row));
            }
            if self.done || !self.has_more {
                self.done = true;
                return Ok(None);
            }
            self.fetch_batch().await?;
        }
    }

    async fn fetch_batch(&mut self) -> Result<()> {
        self.conn
            .write_message(&Request::pull(self.batch, self.qid))
            .await?;
        loop {
            match self.conn.read_message().await? {
                Response::Record(values) => self.buffer.push_back(values),
                Response::Success(meta) => {
                    self.has_more = meta
                        .get("has_more")
                        .and_then(BoltValue::as_bool)
                        .unwrap_or(false);
                    if !self.has_more {
                        self.summary = Some(meta);
                    }
                    return Ok(());
                }
                Response::Failure { code, message } => {
                    self.done = true;
                    return Err(self.conn.fail_reset(code, message).await);
                }
                Response::Ignored => {
                    self.done = true;
                    return Err(BoltError::Protocol("PULL ignored by server".into()));
                }
            }
        }
    }

    /// DISCARD whatever remains and return the summary metadata.
    pub async fn finish(mut self) -> Result<HashMap<String, BoltValue>> {
        if let Some(summary) = self.summary.take() {
            self.done = true;
            return Ok(summary);
        }
        if self.done {
            return Ok(HashMap::new());
        }
        self.done = true;
        self.conn
            .write_message(&Request::discard(-1, self.qid))
            .await?;
        loop {
            match self.conn.read_message().await? {
                Response::Success(meta) => return Ok(meta),
                Response::Record(_) => {}
                Response::Failure { code, message } => {
                    return Err(self.conn.fail_reset(code, message).await);
                }
                Response::Ignored => {
                    return Err(BoltError::Protocol("DISCARD ignored by server".into()));
                }
            }
        }
    }
}

impl Drop for RecordStream<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.conn.needs_reset = true;
        }
    }
}

fn validate_batch(batch: i64) -> Result<()> {
    if batch == 0 || batch < -1 {
        return Err(BoltError::Protocol(format!(
            "invalid batch size {batch}; use -1 or >= 1"
        )));
    }
    Ok(())
}

/// Read an optional string entry from a metadata map.
fn meta_str(meta: &HashMap<String, BoltValue>, key: &str) -> Option<String> {
    meta.get(key)
        .and_then(BoltValue::as_str)
        .map(ToString::to_string)
}

/// Require a SUCCESS reply, returning its metadata; map FAILURE/other into an
/// error tagged with `ctx` (the request that was awaiting the reply).
fn expect_success(response: Response, ctx: &str) -> Result<HashMap<String, BoltValue>> {
    match response {
        Response::Success(meta) => Ok(meta),
        Response::Failure { code, message } => Err(BoltError::Failure { code, message }),
        other => Err(BoltError::Protocol(format!(
            "unexpected {ctx} response: {other:?}"
        ))),
    }
}

fn extract_columns(meta: &HashMap<String, BoltValue>) -> Vec<String> {
    meta.get("fields")
        .map(BoltValue::as_strings)
        .unwrap_or_default()
}

fn map_eof(e: std::io::Error) -> BoltError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        BoltError::Closed("connection closed mid-message".into())
    } else {
        BoltError::Io(e)
    }
}

#[cfg(test)]
mod test;
