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

#[tokio::test]
async fn acquire_surfaces_permanent_errors_without_evicting() {
    let pool = RoutedPool::new(vec!["seed:7687".into()], None, 1, |_addr| async {
        Err::<BoltConnection, _>(BoltError::Failure {
            code: "Neo.ClientError.Security.Unauthorized".into(),
            message: "bad credentials".into(),
        })
    });
    {
        let mut state = pool.inner.state.lock().await;
        state.table = RoutingTable {
            ttl_seconds: 300,
            db: None,
            routers: vec!["seed:7687".into()],
            readers: vec!["r1:7687".into(), "r2:7687".into()],
            writers: vec!["w1:7687".into()],
        };
        state.fetched_at = Some(Instant::now());
    }

    let err = pool.read().await.err().expect("bad credentials");
    assert!(
        matches!(&err, BoltError::Failure { code, .. } if code.contains("Unauthorized")),
        "{err:?}"
    );
    let state = pool.inner.state.lock().await;
    assert_eq!(state.table.readers.len(), 2, "servers are not evicted");
}

#[test]
fn transient_classification() {
    let failure = |code: &str| BoltError::Failure {
        code: code.into(),
        message: String::new(),
    };
    assert!(is_transient(&failure(
        "Neo.TransientError.General.DatabaseUnavailable"
    )));
    assert!(is_transient(&failure("Neo.ClientError.Cluster.NotALeader")));
    assert!(!is_transient(&failure(
        "Neo.ClientError.Security.Unauthorized"
    )));
    assert!(is_transient(&BoltError::Closed("eof".into())));
    assert!(!is_transient(&BoltError::Protocol("junk".into())));
}
