//! Pool behaviour against a scripted fake server; no database needed.

#[path = "support/fake_bolt.rs"]
mod fake_bolt;
#[cfg(feature = "tls-rustls")]
#[path = "support/pki.rs"]
mod pki;

use std::collections::HashMap;
use std::sync::Arc;

use boltwire::{BoltConnection, Pool};
use fake_bolt::FakeBolt;

fn pool(server: &FakeBolt, size: usize) -> Pool {
    let addr = server.addr();
    Pool::new(size, move || {
        let addr = addr.clone();
        async move { BoltConnection::connect(addr, None).await }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn returns_are_not_lost_under_contention() {
    const SIZE: usize = 4;
    let server = FakeBolt::start().await;
    let pool = Arc::new(pool(&server, SIZE));

    let tasks: Vec<_> = (0..32)
        .map(|_| {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move {
                for _ in 0..100 {
                    let mut conn = pool.get().await.expect("checkout");
                    conn.run("q", HashMap::new()).await.expect("query");
                }
            })
        })
        .collect();
    for task in tasks {
        task.await.expect("task");
    }

    // Every connection went back to the pool, so no more than SIZE were
    // ever opened.
    assert!(
        server.accepted() <= SIZE,
        "{} connections opened for a pool of {SIZE}",
        server.accepted()
    );
}

fn retrying_pool(server: &FakeBolt, attempts: u8) -> Pool {
    let addr = server.addr();
    Pool::with_config(
        boltwire::PoolConfig {
            max_size: 1,
            connect_attempts: attempts,
            ..boltwire::PoolConfig::default()
        },
        move || {
            let addr = addr.clone();
            async move {
                BoltConnection::connect(addr, Some(boltwire::Auth::basic("neo4j", "wrong"))).await
            }
        },
    )
}

#[tokio::test]
async fn authentication_failure_is_not_retried() {
    let server = FakeBolt::start_with(fake_bolt::Options {
        logon_failure: Some((
            "Neo.ClientError.Security.Unauthorized".into(),
            "The client is unauthorized due to authentication failure.".into(),
        )),
        ..fake_bolt::Options::default()
    })
    .await;
    let pool = retrying_pool(&server, 5);

    let err = pool.get().await.err().expect("wrong password");
    assert!(
        matches!(&err, boltwire::BoltError::Failure { code, .. } if code.contains("Unauthorized")),
        "{err:?}"
    );
    assert!(!err.is_transient());
    assert_eq!(server.accepted(), 1, "a wrong password is not retried");
}

#[tokio::test]
async fn transient_failures_are_still_retried() {
    let server = FakeBolt::start_with(fake_bolt::Options {
        logon_failure: Some((
            "Neo.TransientError.General.DatabaseUnavailable".into(),
            "starting up".into(),
        )),
        ..fake_bolt::Options::default()
    })
    .await;
    let pool = retrying_pool(&server, 3);

    let err = pool.get().await.err().expect("never comes up");
    assert!(err.is_transient(), "{err:?}");
    assert_eq!(server.accepted(), 3, "transient failures use every attempt");
}

#[cfg(feature = "tls-rustls")]
#[tokio::test]
async fn untrusted_certificate_is_not_retried() {
    let pki = pki::pki();
    let server = FakeBolt::start_with(fake_bolt::Options {
        tls: Some(std::sync::Arc::clone(&pki.server)),
        ..fake_bolt::Options::default()
    })
    .await;
    let addr = server.addr();
    // Default roots only: the private CA is not trusted.
    let tls = Arc::new(
        boltwire::RustlsProvider::builder()
            .build()
            .expect("provider"),
    );
    let pool = Pool::with_config(
        boltwire::PoolConfig {
            max_size: 1,
            connect_attempts: 5,
            ..boltwire::PoolConfig::default()
        },
        move || {
            let (addr, tls) = (addr.clone(), Arc::clone(&tls));
            async move { BoltConnection::connect_tls(addr, "localhost", None, tls.as_ref()).await }
        },
    );

    let err = pool.get().await.err().expect("untrusted certificate");
    assert!(matches!(err, boltwire::BoltError::Tls(_)), "{err:?}");
    assert!(!err.is_transient());
    assert_eq!(server.accepted(), 1, "a bad certificate is not retried");
}

#[cfg(feature = "tls-rustls")]
#[tokio::test]
async fn tls_handshake_cut_by_the_network_is_retried() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Accept, then hang up before the handshake completes.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(socket);
        }
    });

    let tls = Arc::new(
        boltwire::RustlsProvider::builder()
            .build()
            .expect("provider"),
    );
    let pool = Pool::with_config(
        boltwire::PoolConfig {
            max_size: 1,
            connect_attempts: 3,
            ..boltwire::PoolConfig::default()
        },
        move || {
            let (addr, tls) = (addr.clone(), Arc::clone(&tls));
            async move { BoltConnection::connect_tls(addr, "localhost", None, tls.as_ref()).await }
        },
    );

    let err = pool.get().await.err().expect("server hangs up");
    assert!(err.is_transient(), "{err:?}");
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
}
