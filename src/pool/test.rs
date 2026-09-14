use super::*;
use std::sync::atomic::{AtomicU32, Ordering};

#[tokio::test]
async fn mint_backs_off_and_counts_attempts() {
    let attempts = Arc::new(AtomicU32::new(0));
    let seen = attempts.clone();
    let pool = Pool::with_config(
        PoolConfig { max_size: 1, connect_attempts: 3, ..PoolConfig::default() },
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
