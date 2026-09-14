use super::RoutingTable;

#[test]
fn remove_evicts_from_all_roles() {
    let mut t = RoutingTable {
        ttl_seconds: 300,
        db: None,
        routers: vec!["a:7687".into(), "b:7687".into()],
        readers: vec!["a:7687".into(), "b:7687".into()],
        writers: vec!["a:7687".into()],
    };
    t.remove("a:7687");
    assert_eq!(t.routers, vec!["b:7687".to_string()]);
    assert_eq!(t.readers, vec!["b:7687".to_string()]);
    assert!(t.writers.is_empty());
}
