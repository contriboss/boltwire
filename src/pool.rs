//! Connection pool. Transport-agnostic: the factory mints connections, so
//! plain TCP, TLS, or anything else pools the same way.

use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono_machines::{BackoffStrategy, ExponentialBackoff};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::connection::BoltConnection;
use crate::error::{BoltError, Result};

type Factory =
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<BoltConnection>> + Send>> + Send + Sync;

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_size: usize,
    /// Idle connections older than this are closed on checkout.
    pub idle_timeout: Option<Duration>,
    /// Connections older than this are recycled instead of reused.
    pub max_lifetime: Option<Duration>,
    /// Connect attempts before giving up (exponential backoff between tries).
    pub connect_attempts: u8,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_size: 8,
            idle_timeout: Some(Duration::from_mins(5)),
            max_lifetime: Some(Duration::from_hours(1)),
            connect_attempts: 3,
        }
    }
}

struct Idle {
    conn: BoltConnection,
    created_at: Instant,
    idled_at: Instant,
}

#[derive(Clone)]
pub struct Pool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    factory: Box<Factory>,
    config: PoolConfig,
    idle: Mutex<Vec<Idle>>,
    permits: Arc<Semaphore>,
}

impl Pool {
    /// `max_size` connections with default timeouts/backoff.
    pub fn new<F, Fut>(max_size: usize, factory: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<BoltConnection>> + Send + 'static,
    {
        Self::with_config(
            PoolConfig {
                max_size,
                ..PoolConfig::default()
            },
            factory,
        )
    }

    pub fn with_config<F, Fut>(config: PoolConfig, factory: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<BoltConnection>> + Send + 'static,
    {
        Self {
            inner: Arc::new(PoolInner {
                factory: Box::new(move || Box::pin(factory())),
                permits: Arc::new(Semaphore::new(config.max_size.max(1))),
                config,
                idle: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Checkout. Idle connections are aged out (idle/lifetime) then RESET-probed;
    /// dead ones are discarded and a fresh one is minted with backoff.
    pub async fn get(&self) -> Result<PooledConnection> {
        let permit = self
            .inner
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| BoltError::Closed("pool closed".into()))?;

        loop {
            let Some(idle) = self.inner.idle.lock().await.pop() else {
                break;
            };
            if self.expired(idle.created_at, idle.idled_at) {
                continue;
            }
            let mut conn = idle.conn;
            if conn.reset().await.is_ok() {
                return Ok(self.wrap(conn, idle.created_at, permit));
            }
        }

        let conn = self.mint().await?;
        Ok(self.wrap(conn, Instant::now(), permit))
    }

    fn expired(&self, created_at: Instant, idled_at: Instant) -> bool {
        let cfg = &self.inner.config;
        cfg.idle_timeout.is_some_and(|t| idled_at.elapsed() > t)
            || cfg.max_lifetime.is_some_and(|t| created_at.elapsed() > t)
    }

    async fn mint(&self) -> Result<BoltConnection> {
        let backoff = ExponentialBackoff::new()
            .base_delay_ms(100)
            .max_delay_ms(2000)
            .max_attempts(self.inner.config.connect_attempts);
        let mut attempt = 1;
        loop {
            match (self.inner.factory)().await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    let delay = backoff.delay(attempt, &mut rand::rng());
                    match delay {
                        Some(delay_ms) => {
                            bolt_debug!(attempt, delay_ms, error = %e, "connect failed; backing off");
                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            attempt += 1;
                        }
                        None => return Err(e),
                    }
                }
            }
        }
    }

    fn wrap(
        &self,
        conn: BoltConnection,
        created_at: Instant,
        permit: OwnedSemaphorePermit,
    ) -> PooledConnection {
        PooledConnection {
            conn: Some(conn),
            created_at,
            inner: self.inner.clone(),
            _permit: permit,
        }
    }
}

/// A checked-out connection; returns to the pool on drop.
pub struct PooledConnection {
    conn: Option<BoltConnection>,
    created_at: Instant,
    inner: Arc<PoolInner>,
    _permit: OwnedSemaphorePermit,
}

impl PooledConnection {
    /// Take the connection out of pool management permanently.
    ///
    /// # Panics
    /// If already detached (impossible through the public API).
    #[must_use]
    pub fn detach(mut self) -> BoltConnection {
        self.conn.take().expect("connection already detached")
    }
}

impl Deref for PooledConnection {
    type Target = BoltConnection;
    fn deref(&self) -> &BoltConnection {
        self.conn.as_ref().expect("connection already detached")
    }
}

impl DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut BoltConnection {
        self.conn.as_mut().expect("connection already detached")
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            // try_lock: on contention the conn is dropped and the next
            // checkout mints a fresh one. Never blocks in Drop.
            if let Ok(mut idle) = self.inner.idle.try_lock() {
                idle.push(Idle {
                    conn,
                    created_at: self.created_at,
                    idled_at: Instant::now(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn mint_backs_off_and_counts_attempts() {
        let attempts = Arc::new(AtomicU32::new(0));
        let seen = attempts.clone();
        let pool = Pool::with_config(
            PoolConfig {
                max_size: 1,
                connect_attempts: 3,
                ..PoolConfig::default()
            },
            move || {
                seen.fetch_add(1, Ordering::SeqCst);
                async { Err::<BoltConnection, _>(BoltError::Closed("down".into())) }
            },
        );
        assert!(pool.get().await.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn expiry_rules() {
        let pool = Pool::with_config(
            PoolConfig {
                max_size: 1,
                idle_timeout: Some(Duration::from_secs(10)),
                max_lifetime: Some(Duration::from_secs(100)),
                connect_attempts: 1,
            },
            || async { Err::<BoltConnection, _>(BoltError::Closed("unused".into())) },
        );
        let now = Instant::now();
        let old = now.checked_sub(Duration::from_hours(1)).unwrap();
        assert!(pool.expired(now, old)); // idle too long
        assert!(pool.expired(old, now)); // lived too long
        assert!(!pool.expired(now, now)); // fresh
    }
}
