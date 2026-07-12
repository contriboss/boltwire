# boltwire

A **pure-Rust, async** [Bolt protocol](https://neo4j.com/docs/bolt/current/bolt/)
driver for **Neo4j** and **Memgraph**. Ported from
[ActiveCypher](https://github.com/seuros/activecypher)'s battle-tested Ruby Bolt
stack - same PackStream codec, same Memgraph handling,same bugs. 
Find them here, fix them everywhere.

## Usage

```rust
use boltwire::{Auth, BoltConnection, BoltValue};
use std::collections::HashMap;

# async fn demo() -> boltwire::Result<()> {
let mut conn = BoltConnection::connect(
    "127.0.0.1:7687",
    Some(Auth::basic("memgraph", "password")),
).await?;

let mut params = HashMap::new();
params.insert("id".into(), BoltValue::Int(1));

let result = conn.run("MATCH (n) WHERE id(n) = $id RETURN n", params).await?;
for row in result.rows_as_maps() {
    println!("{:?}", row["n"]);
}
conn.close().await?;
# Ok(())
# }
```

### Transactions

```rust
let mut tx = conn.begin().await?;
tx.run("CREATE (:Account {id: 1})", HashMap::new()).await?;
tx.run("CREATE (:Account {id: 2})", HashMap::new()).await?;
let bookmark = tx.commit().await?;   // or tx.rollback().await?
```

### Streaming

```rust
let mut stream = conn.run_stream("MATCH (n) RETURN n", HashMap::new(), 1000).await?;
while let Some(record) = stream.next().await? {
    // one batch of 1000 in memory at a time
}
let summary = stream.finish().await?;
```

### Pooling

```rust
let pool = Pool::new(8, move || {
    let addr = addr.clone();
    let auth = auth.clone();
    async move { BoltConnection::connect(addr, auth).await }
});
let mut conn = pool.get().await?;    // returns to the pool on drop
```

Cluster-aware, when your servers come in herds:

```rust
let routed = RoutedPool::new(vec!["core1:7687".into()], None, 8, connect_fn);
let mut r = routed.read().await?;    // round-robin over READ servers
let mut w = routed.write().await?;   // round-robin over WRITE servers
```

### TLS (`--features tls-rustls`)

```rust
use boltwire::RustlsProvider;

let tls = RustlsProvider::builder()
    .add_root_pem(&std::fs::read("ca.pem")?)      // pin a private CA (optional)
    // .danger_accept_invalid_certs(true)         // you know what this does
    .build()?;

let mut conn = BoltConnection::connect_tls(
    "db.example.com:7687", "db.example.com", Some(auth), &tls,
).await?;
```

Any type implementing `boltwire::TlsProvider` slots in the same way; `tls-rustls`
is just the backend i use.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT).
