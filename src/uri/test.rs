use super::*;

#[test]
fn parses_full_uri() {
    let c = Config::from_uri("bolt+s://neo:pass@db.example.com:9999?db=movies").unwrap();
    assert_eq!(c.scheme, Scheme::BoltS);
    assert_eq!(c.host, "db.example.com");
    assert_eq!(c.port, 9999);
    assert_eq!(c.auth.as_ref().unwrap().principal, "neo");
    assert_eq!(c.db.as_deref(), Some("movies"));
}

#[test]
fn defaults_port_and_optionals() {
    let c = Config::from_uri("bolt://localhost").unwrap();
    assert_eq!(
        (c.port, c.auth.is_none(), c.db.is_none()),
        (7687, true, true)
    );
}

#[test]
fn neo4j_scheme_is_routed() {
    assert!(Config::from_uri("neo4j://core1").unwrap().scheme.routed());
    assert!(!Config::from_uri("bolt://core1").unwrap().scheme.routed());
}

#[test]
fn ipv6_hosts() {
    let c = Config::from_uri("bolt://[::1]:9999").unwrap();
    assert_eq!((c.host.as_str(), c.port), ("::1", 9999));
    assert_eq!(c.addr(), "[::1]:9999");
    let c = Config::from_uri("bolt://[fe80::1]").unwrap();
    assert_eq!((c.host.as_str(), c.port), ("fe80::1", 7687));
    assert!(Config::from_uri("bolt://[::1").is_err());
}

#[test]
fn rejects_garbage() {
    assert!(Config::from_uri("http://x").is_err());
    assert!(Config::from_uri("bolt://").is_err());
    assert!(Config::from_uri("bolt://host:notaport").is_err());
    assert!(Config::from_uri("no-scheme").is_err());
}

#[test]
fn rejects_unbracketed_ipv6() {
    assert!(Config::from_uri("bolt://::1").is_err());
    assert!(Config::from_uri("bolt://fe80::1:7687").is_err());
}

#[test]
fn splits_routing_table_addresses() {
    assert_eq!(split_host_port("[::1]:7687"), Ok(("::1", Some(7687))));
    assert_eq!(split_host_port("[fe80::1]"), Ok(("fe80::1", None)));
    assert_eq!(
        split_host_port("core1.example:7687"),
        Ok(("core1.example", Some(7687)))
    );
    assert_eq!(split_host_port("10.0.0.5"), Ok(("10.0.0.5", None)));
    assert!(split_host_port("[::1]x").is_err());
    assert!(split_host_port("::1:7687").is_err());
    assert!(split_host_port(":7687").is_err());
}
