use super::*;

fn roundtrip(v: &BoltValue) -> BoltValue {
    let mut buf = Vec::new();
    pack(v, &mut buf).unwrap();
    Reader::new(&buf).unpack().unwrap()
}

#[test]
fn scalars_roundtrip() {
    for v in [
        BoltValue::Null,
        BoltValue::Bool(true),
        BoltValue::Bool(false),
        BoltValue::Float(std::f64::consts::PI),
        BoltValue::String("héllo".into()),
    ] {
        assert_eq!(roundtrip(&v), v);
    }
}

#[test]
fn integer_boundaries_roundtrip() {
    for i in [
        0,
        -1,
        -16,
        127,
        -17,
        -128,
        128,
        255,
        32_767,
        -32_768,
        32_768,
        2_147_483_647,
        -2_147_483_648,
        2_147_483_648,
        i64::MAX,
        i64::MIN,
    ] {
        assert_eq!(roundtrip(&BoltValue::Int(i)), BoltValue::Int(i), "int {i}");
    }
}

#[test]
fn tiny_int_encoding_matches_spec() {
    // -16..=127 must be exactly one byte on the wire.
    for i in -16_i64..=127 {
        let mut buf = Vec::new();
        pack(&BoltValue::Int(i), &mut buf).unwrap();
        assert_eq!(buf.len(), 1, "tiny int {i} should be 1 byte, got {buf:?}");
    }
}

#[test]
fn collections_roundtrip() {
    let list = BoltValue::List(vec![BoltValue::Int(1), BoltValue::String("x".into())]);
    assert_eq!(roundtrip(&list), list);

    let mut m = HashMap::new();
    m.insert("n".to_string(), BoltValue::Int(-1));
    let map = BoltValue::Map(m);
    assert_eq!(roundtrip(&map), map);
}

#[test]
fn structure_roundtrip() {
    let node = BoltValue::Structure {
        signature: crate::value::sig::NODE,
        fields: vec![BoltValue::Int(42), BoltValue::List(vec![BoltValue::String("Person".into())])],
    };
    assert_eq!(roundtrip(&node), node);
}

#[test]
fn large_payloads_use_32bit_markers() {
    // > 65,535 bytes: must encode (STRING_32) and roundtrip.
    let s = BoltValue::String("x".repeat(70_000));
    let mut buf = Vec::new();
    pack(&s, &mut buf).unwrap();
    assert_eq!(buf[0], STRING_32);
    assert_eq!(Reader::new(&buf).unpack().unwrap(), s);

    // > 65,535 elements: LIST_32.
    let l = BoltValue::List(vec![BoltValue::Int(1); 70_000]);
    buf.clear();
    pack(&l, &mut buf).unwrap();
    assert_eq!(buf[0], LIST_32);
    assert_eq!(Reader::new(&buf).unpack().unwrap(), l);
}

#[test]
fn known_wire_bytes() {
    // Cross-check a couple of exact encodings against the Bolt spec.
    let mut buf = Vec::new();
    pack(&BoltValue::Int(-1), &mut buf).unwrap();
    assert_eq!(buf, vec![0xFF]);

    buf.clear();
    pack(&BoltValue::Int(1234), &mut buf).unwrap();
    assert_eq!(buf, vec![INT_16, 0x04, 0xD2]);

    buf.clear();
    pack(&BoltValue::String("Størmy".into()), &mut buf).unwrap();
    // 7 UTF-8 bytes (2 for the multibyte char) -> tiny string marker 0x80|7.
    assert_eq!(buf[0], 0x87);
}

mod fuzz_smoke {
    use crate::packstream::*;

    // Deterministic xorshift so failures reproduce.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn byte(&mut self) -> u8 {
            (self.next() & 0xFF) as u8
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut rng = Rng(0x5eed_b017);
        for _ in 0..50_000 {
            let len = (rng.next() % 64) as usize;
            let buf: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            let _ = Reader::new(&buf).unpack(); // Err is fine; panic is not
        }
    }

    #[test]
    fn mutated_valid_encodings_never_panic() {
        let mut base = Vec::new();
        let mut map = HashMap::new();
        map.insert("k".to_string(), BoltValue::List(vec![BoltValue::Int(1); 20]));
        pack(
            &BoltValue::Structure { signature: 0x70, fields: vec![BoltValue::Map(map)] },
            &mut base,
        )
        .unwrap();

        let mut rng = Rng(0xb01d_face);
        for _ in 0..50_000 {
            let mut buf = base.clone();
            let flips = 1 + (rng.next() % 4) as usize;
            for _ in 0..flips {
                let i = (rng.next() as usize) % buf.len();
                buf[i] = rng.byte();
            }
            let _ = Reader::new(&buf).unpack();
        }
    }

    #[test]
    fn lying_size_headers_do_not_allocate() {
        // Claims 4 billion elements with 1 byte of payload behind it.
        for marker in [LIST_32, MAP_32, STRING_32, STRUCT_32] {
            let buf = [marker, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
            assert!(Reader::new(&buf).unpack().is_err());
        }
    }
}
