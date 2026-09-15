use super::*;

fn node() -> BoltValue {
    let mut props = HashMap::new();
    props.insert("name".to_string(), BoltValue::String("Neo".into()));
    BoltValue::Structure {
        signature: sig::NODE,
        fields: vec![
            BoltValue::Int(7),
            BoltValue::List(vec![BoltValue::String("Person".into())]),
            BoltValue::Map(props),
            BoltValue::String("4:abc:7".into()),
        ],
    }
}

#[test]
fn node_view() {
    let v = node();
    let n = v.as_node().unwrap();
    assert_eq!(n.id, 7);
    assert_eq!(n.label_strs(), ["Person"]);
    assert_eq!(n.prop("name").and_then(BoltValue::as_str), Some("Neo"));
    assert_eq!(n.element_id, Some("4:abc:7"));
    assert!(v.as_relationship().is_none());
}

#[test]
fn path_view() {
    let rel = BoltValue::Structure {
        signature: sig::UNBOUND_RELATIONSHIP,
        fields: vec![
            BoltValue::Int(1),
            BoltValue::String("KNOWS".into()),
            BoltValue::Map(HashMap::new()),
        ],
    };
    let path = BoltValue::Structure {
        signature: sig::PATH,
        fields: vec![
            BoltValue::List(vec![node(), node()]),
            BoltValue::List(vec![rel]),
            BoltValue::List(vec![BoltValue::Int(1), BoltValue::Int(1)]),
        ],
    };
    let p = path.as_path().unwrap();
    assert_eq!((p.nodes.len(), p.relationships.len()), (2, 1));
    assert_eq!(p.relationships[0].type_, "KNOWS");
    assert_eq!(p.indices, [1, 1]);
}

#[test]
fn temporal_views() {
    let date = BoltValue::Structure {
        signature: sig::DATE,
        fields: vec![BoltValue::Int(20_000)],
    };
    assert_eq!(date.as_date_days(), Some(20_000));

    let dur = BoltValue::Structure {
        signature: sig::DURATION,
        fields: vec![
            BoltValue::Int(0),
            BoltValue::Int(2),
            BoltValue::Int(30),
            BoltValue::Int(500),
        ],
    };
    assert_eq!(
        dur.as_duration(),
        Some(DurationRef {
            months: 0,
            days: 2,
            seconds: 30,
            nanoseconds: 500
        })
    );

    let pt = BoltValue::Structure {
        signature: sig::POINT_2D,
        fields: vec![
            BoltValue::Int(4326),
            BoltValue::Float(1.5),
            BoltValue::Float(2.5),
        ],
    };
    assert_eq!(
        pt.as_point(),
        Some(PointRef {
            srid: 4326,
            x: 1.5,
            y: 2.5,
            z: None
        })
    );
}
