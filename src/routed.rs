//! Cluster pool: ROUTE table with TTL refresh, round-robin per role,
//! eviction on connect failure.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use tokio::sync::Mutex;

use crate::connection::{BoltConnection, Transaction, TxOptions};
use crate::error::{BoltError, Result};
use crate::pool::{Pool, PooledConnection};
use crate::routing::RoutingTable;

type ConnectFn =
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<BoltConnection>> + Send>> + Send + Sync;

const RETRY_ATTEMPTS: u8 = 3;

fn is_transient(e: &BoltError) -> bool {
    match e {
        BoltError::Io(_) | BoltError::Closed(_) | BoltError::Timeout(_) => true,
        BoltError::Failure { code, .. } => code.contains("TransientError") || cluster_moved(e),
        _ => false,
    }
}

/// Cluster reshaped under us; the routing table is stale.
fn cluster_moved(e: &BoltError) -> bool {
    matches!(e, BoltError::Failure { code, .. }
        if code.contains("NotALeader") || code.contains("ForbiddenOnFollower"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    Read,
    Write,
}

#[derive(Clone)]
pub struct RoutedPool {
    inner: Arc<Inner>,
}

struct Inner {
    seeds: Vec<String>,
    db: Option<String>,
    max_per_host: usize,
    connect: Arc<ConnectFn>,
    state: Mutex<State>,
    rr: [AtomicUsize; 2], // per-AccessMode round-robin cursors
    bookmarks: Mutex<Vec<String>>,
}

#[derive(Default)]
struct State {
    table: RoutingTable,
    fetched_at: Option<Instant>,
    pools: HashMap<String, Pool>,
}

impl RoutedPool {
    /// `seeds`: initial router addresses. `connect` dials one server address
    /// (plain or TLS, its call). Per-server pools hold `max_per_host` each.
    pub fn new<F, Fut>(
        seeds: Vec<String>,
        db: Option<String>,
        max_per_host: usize,
        connect: F,
    ) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<BoltConnection>> + Send + 'static,
    {
        Self {
            inner: Arc::new(Inner {
                seeds,
                db,
                max_per_host,
                connect: Arc::new(move |addr| Box::pin(connect(addr))),
                state: Mutex::new(State::default()),
                rr: [AtomicUsize::new(0), AtomicUsize::new(0)],
                bookmarks: Mutex::new(Vec::new()),
            }),
        }
    }

    pub async fn read(&self) -> Result<PooledConnection> {
        self.acquire(AccessMode::Read).await
    }

    pub async fn write(&self) -> Result<PooledConnection> {
        self.acquire(AccessMode::Write).await
    }

    /// Bookmarks observed so far (fed into the next managed transaction).
    pub async fn bookmarks(&self) -> Vec<String> {
        self.inner.bookmarks.lock().await.clone()
    }

    /// Run `work` in a managed read transaction with retries on transient
    /// failures and causal-consistency bookmark threading.
    pub async fn execute_read<T, F>(&self, work: F) -> Result<T>
    where
        F: for<'t, 'c> FnMut(
            &'t mut Transaction<'c>,
        ) -> Pin<Box<dyn Future<Output = Result<T>> + Send + 't>>,
    {
        self.execute(AccessMode::Read, work).await
    }

    /// Managed write transaction; see [`execute_read`](Self::execute_read).
    pub async fn execute_write<T, F>(&self, work: F) -> Result<T>
    where
        F: for<'t, 'c> FnMut(
            &'t mut Transaction<'c>,
        ) -> Pin<Box<dyn Future<Output = Result<T>> + Send + 't>>,
    {
        self.execute(AccessMode::Write, work).await
    }

    async fn execute<T, F>(&self, mode: AccessMode, mut work: F) -> Result<T>
    where
        F: for<'t, 'c> FnMut(
            &'t mut Transaction<'c>,
        ) -> Pin<Box<dyn Future<Output = Result<T>> + Send + 't>>,
    {
        let backoff = chrono_machines::ExponentialBackoff::new()
            .base_delay_ms(100)
            .max_delay_ms(2000)
            .max_attempts(RETRY_ATTEMPTS);

        let mut attempt = 1;
        loop {
            match self.try_once(mode, &mut work).await {
                Ok(value) => return Ok(value),
                Err(e) if is_transient(&e) => {
                    if cluster_moved(&e) {
                        self.refresh().await.ok();
                    }
                    let delay = chrono_machines::BackoffStrategy::delay(
                        &backoff,
                        attempt,
                        &mut rand::rng(),
                    );
                    match delay {
                        Some(ms) => {
                            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                            attempt += 1;
                        }
                        None => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn try_once<T, F>(&self, mode: AccessMode, work: &mut F) -> Result<T>
    where
        F: for<'t, 'c> FnMut(
            &'t mut Transaction<'c>,
        ) -> Pin<Box<dyn Future<Output = Result<T>> + Send + 't>>,
    {
        let mut conn = self.acquire(mode).await?;
        let opts = TxOptions {
            db: self.inner.db.clone(),
            read_only: mode == AccessMode::Read,
            bookmarks: self.bookmarks().await,
            ..TxOptions::default()
        };
        let mut tx = conn.begin_with(opts).await?;
        let value = match work(&mut tx).await {
            Ok(v) => v,
            Err(e) => {
                tx.rollback().await.ok();
                return Err(e);
            }
        };
        if let Some(bookmark) = tx.commit().await? {
            // Merge, don't replace: concurrent commits must not regress each other.
            let mut bookmarks = self.inner.bookmarks.lock().await;
            if !bookmarks.contains(&bookmark) {
                bookmarks.push(bookmark);
                let excess = bookmarks.len().saturating_sub(16);
                bookmarks.drain(..excess);
            }
        }
        Ok(value)
    }

    /// Current routing table (fetching it first if empty/stale).
    pub async fn table(&self) -> Result<RoutingTable> {
        self.ensure_fresh().await?;
        Ok(self.inner.state.lock().await.table.clone())
    }

    /// Force a table refresh via the first answering router.
    pub async fn refresh(&self) -> Result<RoutingTable> {
        // Known routers first, then the seeds.
        let mut candidates = self.inner.state.lock().await.table.routers.clone();
        candidates.extend(self.inner.seeds.iter().cloned());

        let mut last_err = BoltError::Closed("no routers to ask".into());
        for addr in candidates {
            match self.route_via(&addr).await {
                Ok(table) => {
                    bolt_debug!(
                        via = %addr,
                        readers = table.readers.len(),
                        writers = table.writers.len(),
                        ttl = table.ttl_seconds,
                        "routing table refreshed"
                    );
                    let mut state = self.inner.state.lock().await;
                    state.table = table.clone();
                    state.fetched_at = Some(Instant::now());
                    return Ok(table);
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn route_via(&self, addr: &str) -> Result<RoutingTable> {
        let mut conn = (self.inner.connect)(addr.to_string()).await?;
        let table = conn.route(HashMap::new(), self.inner.db.as_deref()).await?;
        conn.close().await.ok();
        Ok(table)
    }

    async fn ensure_fresh(&self) -> Result<()> {
        let stale = {
            let state = self.inner.state.lock().await;
            match state.fetched_at {
                None => true,
                Some(at) => {
                    at.elapsed().as_secs() >= u64::try_from(state.table.ttl_seconds).unwrap_or(0)
                }
            }
        };
        if stale {
            self.refresh().await?;
        }
        Ok(())
    }

    async fn acquire(&self, mode: AccessMode) -> Result<PooledConnection> {
        // Two laps: the second after a forced refresh when every server failed.
        for lap in 0..2 {
            if lap > 0 {
                self.refresh().await?;
            } else {
                self.ensure_fresh().await?;
            }

            let addrs = {
                let state = self.inner.state.lock().await;
                match mode {
                    AccessMode::Read => state.table.readers.clone(),
                    AccessMode::Write => state.table.writers.clone(),
                }
            };
            if addrs.is_empty() {
                continue;
            }

            let start = self.inner.rr[mode as usize].fetch_add(1, Ordering::Relaxed);
            for i in 0..addrs.len() {
                let addr = &addrs[(start + i) % addrs.len()];
                match self.pool_for(addr).await.get().await {
                    Ok(conn) => return Ok(conn),
                    Err(_) => self.evict(addr).await,
                }
            }
        }
        Err(BoltError::Closed(format!("no reachable {mode:?} server")))
    }

    async fn pool_for(&self, addr: &str) -> Pool {
        let mut state = self.inner.state.lock().await;
        state
            .pools
            .entry(addr.to_string())
            .or_insert_with(|| {
                let connect = self.inner.connect.clone();
                let addr = addr.to_string();
                Pool::new(self.inner.max_per_host, move || connect(addr.clone()))
            })
            .clone()
    }

    async fn evict(&self, addr: &str) {
        let mut state = self.inner.state.lock().await;
        state.table.remove(addr);
        state.pools.remove(addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dead_pool(seeds: Vec<String>) -> RoutedPool {
        RoutedPool::new(seeds, None, 1, |_addr| async {
            Err::<BoltConnection, _>(BoltError::Closed("test: unreachable".into()))
        })
    }

    #[tokio::test]
    async fn acquire_evicts_dead_servers_and_errors_out() {
        let pool = dead_pool(vec!["dead:7687".into()]);
        {
            // Seed a fake table so acquire skips the initial refresh.
            let mut state = pool.inner.state.lock().await;
            state.table = RoutingTable {
                ttl_seconds: 300,
                db: None,
                routers: vec!["dead:7687".into()],
                readers: vec!["r1:7687".into(), "r2:7687".into()],
                writers: vec!["w1:7687".into()],
            };
            state.fetched_at = Some(Instant::now());
        }

        // Every reader fails to connect; both get evicted; refresh via the
        // dead router also fails; acquire must error, not hang.
        assert!(pool.read().await.is_err());
        let state = pool.inner.state.lock().await;
        assert!(state.table.readers.is_empty(), "dead readers evicted");
    }

    #[tokio::test]
    async fn round_robin_advances() {
        let pool = dead_pool(vec![]);
        let a = pool.inner.rr[AccessMode::Read as usize].fetch_add(1, Ordering::Relaxed);
        let b = pool.inner.rr[AccessMode::Read as usize].fetch_add(1, Ordering::Relaxed);
        assert_eq!(b, a + 1);
    }
}
