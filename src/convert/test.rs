use super::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Person {
    name: String,
    age: i64,
    score: f64,
    tags: Vec<String>,
    nickname: Option<String>,
}

fn sample() -> Person {
    Person {
        name: "Neo".into(),
        age: 30,
        score: 9.5,
        tags: vec!["a".into(), "b".into()],
        nickname: None,
    }
}

#[test]
fn struct_roundtrip() {
    let v = to_value(&sample()).unwrap();
    assert!(matches!(v, BoltValue::Map(_)));
    let back: Person = from_value(v).unwrap();
    assert_eq!(back, sample());
}

#[test]
fn params_requires_map() {
    assert!(params(&sample()).unwrap().contains_key("name"));
    assert!(params(&42i64).is_err());
}

#[test]
fn rows_as_deserializes_by_column() {
    #[derive(Deserialize, Debug, PartialEq)]
    struct Row {
        n: i64,
        s: String,
    }
    let result = QueryResult {
        columns: vec!["n".into(), "s".into()],
        records: vec![
            vec![BoltValue::Int(1), BoltValue::String("x".into())],
            vec![BoltValue::Int(2), BoltValue::String("y".into())],
        ],
    };
    let rows: Vec<Row> = result.rows_as().unwrap();
    assert_eq!(
        rows,
        vec![
            Row {
                n: 1,
                s: "x".into()
            },
            Row {
                n: 2,
                s: "y".into()
            }
        ]
    );
}

#[test]
fn structures_refuse_flat_deserialization() {
    let v = BoltValue::Structure {
        signature: 0x4E,
        fields: vec![],
    };
    assert!(from_value::<String>(v).is_err());
}
