//! `PackStream` v1 encode/decode.
//! Spec: <https://neo4j.com/docs/bolt/current/packstream/>

// Casts/unwraps are guarded by the size checks above each call site.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::missing_panics_doc
)]

use crate::error::{BoltError, Result};
use crate::value::BoltValue;
use std::collections::HashMap;

// Marker bytes (subset actually emitted; the reader accepts the 32-bit forms too).
const NULL: u8 = 0xC0;
const FLOAT_64: u8 = 0xC1;
const FALSE: u8 = 0xC2;
const TRUE: u8 = 0xC3;
const INT_8: u8 = 0xC8;
const INT_16: u8 = 0xC9;
const INT_32: u8 = 0xCA;
const INT_64: u8 = 0xCB;
const BYTES_8: u8 = 0xCC;
const BYTES_16: u8 = 0xCD;
const BYTES_32: u8 = 0xCE;

const TINY_STRING: u8 = 0x80;
const STRING_8: u8 = 0xD0;
const STRING_16: u8 = 0xD1;
const STRING_32: u8 = 0xD2;

const TINY_LIST: u8 = 0x90;
const LIST_8: u8 = 0xD4;
const LIST_16: u8 = 0xD5;
const LIST_32: u8 = 0xD6;

const TINY_MAP: u8 = 0xA0;
const MAP_8: u8 = 0xD8;
const MAP_16: u8 = 0xD9;
const MAP_32: u8 = 0xDA;

const TINY_STRUCT: u8 = 0xB0;
const STRUCT_8: u8 = 0xDC;
const STRUCT_16: u8 = 0xDD;
const STRUCT_32: u8 = 0xDE;

// ---- pack ----

/// Serialize a value into `out`.
pub fn pack(value: &BoltValue, out: &mut Vec<u8>) -> Result<()> {
    match value {
        BoltValue::Null => out.push(NULL),
        BoltValue::Bool(true) => out.push(TRUE),
        BoltValue::Bool(false) => out.push(FALSE),
        BoltValue::Int(i) => pack_int(*i, out),
        BoltValue::Float(f) => tagged(out, FLOAT_64, &f.to_be_bytes()),
        BoltValue::String(s) => pack_string(s, out)?,
        BoltValue::Bytes(b) => pack_bytes(b, out),
        BoltValue::List(items) => {
            pack_header(items.len(), TINY_LIST, LIST_8, LIST_16, "list", out)?;
            pack_seq(items, out)?;
        }
        BoltValue::Map(map) => pack_map(map, out)?,
        BoltValue::Structure { signature, fields } => {
            // Structs are size-prefixed by field count, then the signature byte.
            pack_header(
                fields.len(),
                TINY_STRUCT,
                STRUCT_8,
                STRUCT_16,
                "struct",
                out,
            )?;
            out.push(*signature);
            pack_seq(fields, out)?;
        }
    }
    Ok(())
}

/// Pack a sequence of values back to back (list items / struct fields).
fn pack_seq(items: &[BoltValue], out: &mut Vec<u8>) -> Result<()> {
    for item in items {
        pack(item, out)?;
    }
    Ok(())
}

/// Pack a metadata/parameter map without an intermediate `BoltValue::Map`.
pub fn pack_map(map: &HashMap<String, BoltValue>, out: &mut Vec<u8>) -> Result<()> {
    pack_header(map.len(), TINY_MAP, MAP_8, MAP_16, "map", out)?;
    for (k, v) in map {
        pack_string(k, out)?;
        pack(v, out)?;
    }
    Ok(())
}

/// Emit a marker byte followed by its big-endian payload.
fn tagged(out: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    out.push(marker);
    out.extend_from_slice(payload);
}

fn pack_int(i: i64, out: &mut Vec<u8>) {
    // TINY_INT: a bare signed byte for the small range.
    if (-16..=127).contains(&i) {
        out.push((i as i8) as u8);
        return;
    }
    // Otherwise the narrowest width that holds `i`, as marker + big-endian bytes.
    macro_rules! fit {
        ($($lo:literal ..= $hi:literal => ($marker:ident, $ty:ty)),+ $(,)?) => {
            $(if ($lo..=$hi).contains(&i) {
                return tagged(out, $marker, &(i as $ty).to_be_bytes());
            })+
        };
    }
    fit!(
        -128 ..= 127 => (INT_8, i8),
        -32_768 ..= 32_767 => (INT_16, i16),
        -2_147_483_648 ..= 2_147_483_647 => (INT_32, i32),
    );
    tagged(out, INT_64, &i.to_be_bytes());
}

fn pack_string(s: &str, out: &mut Vec<u8>) -> Result<()> {
    let bytes = s.as_bytes();
    pack_header(bytes.len(), TINY_STRING, STRING_8, STRING_16, "string", out)?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn pack_bytes(b: &[u8], out: &mut Vec<u8>) {
    let n = b.len();
    if n < 256 {
        tagged(out, BYTES_8, &(n as u8).to_be_bytes());
    } else if n < 65_536 {
        tagged(out, BYTES_16, &(n as u16).to_be_bytes());
    } else {
        tagged(out, BYTES_32, &(n as u32).to_be_bytes());
    }
    out.extend_from_slice(b);
}

fn pack_header(
    size: usize,
    tiny: u8,
    m8: u8,
    m16: u8,
    label: &str,
    out: &mut Vec<u8>,
) -> Result<()> {
    if size < 16 {
        out.push(tiny | u8::try_from(size).unwrap());
    } else if size < 256 {
        tagged(out, m8, &u8::try_from(size).unwrap().to_be_bytes());
    } else if size < 65_536 {
        tagged(out, m16, &u16::try_from(size).unwrap().to_be_bytes());
    } else if let Ok(size32) = u32::try_from(size) {
        // Markers are consecutive: m32 = m16 + 1 (D0/D1/D2, D4/D5/D6, D8/D9/DA).
        tagged(out, m16 + 1, &size32.to_be_bytes());
    } else {
        return Err(BoltError::Protocol(format!(
            "{label} too large to pack ({size})"
        )));
    }
    Ok(())
}

// ---- unpack ----

/// A cursor over a fully-buffered message body.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| BoltError::Protocol("length overflow".into()))?;
        if end > self.buf.len() {
            return Err(BoltError::Protocol(format!(
                "unexpected end of stream: need {n} bytes at {}, have {}",
                self.pos,
                self.buf.len() - self.pos
            )));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn size(&mut self, n: usize) -> Result<usize> {
        let bytes = self.take(n)?;
        Ok(match n {
            1 => usize::from(bytes[0]),
            2 => usize::from(u16::from_be_bytes([bytes[0], bytes[1]])),
            4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
            _ => return Err(BoltError::Protocol("invalid size width".into())),
        })
    }

    /// Decode the next value.
    pub fn unpack(&mut self) -> Result<BoltValue> {
        let marker = self.u8()?;

        // Tiny positive int 0x00..=0x7F.
        if marker < 0x80 {
            return Ok(BoltValue::Int(i64::from(marker)));
        }
        // Tiny negative int 0xF0..=0xFF -> -16..=-1.
        if marker >= 0xF0 {
            return Ok(BoltValue::Int(i64::from(marker as i8)));
        }

        // Reads a `$w`-byte big-endian size, then unpacks a container of that len.
        macro_rules! sized {
            ($w:literal, $method:ident) => {{
                let n = self.size($w)?;
                self.$method(n)
            }};
        }

        let low = usize::from(marker & 0x0F);
        match marker & 0xF0 {
            TINY_STRING => return self.unpack_string(low),
            TINY_LIST => return self.unpack_list(low),
            TINY_MAP => return self.unpack_map(low),
            TINY_STRUCT => return self.unpack_struct(low),
            _ => {}
        }

        match marker {
            NULL => Ok(BoltValue::Null),
            TRUE => Ok(BoltValue::Bool(true)),
            FALSE => Ok(BoltValue::Bool(false)),
            FLOAT_64 => {
                let b = self.take(8)?;
                Ok(BoltValue::Float(f64::from_be_bytes(b.try_into().unwrap())))
            }
            INT_8 => Ok(BoltValue::Int(i64::from(self.take(1)?[0] as i8))),
            INT_16 => {
                let b = self.take(2)?;
                Ok(BoltValue::Int(i64::from(i16::from_be_bytes(
                    b.try_into().unwrap(),
                ))))
            }
            INT_32 => {
                let b = self.take(4)?;
                Ok(BoltValue::Int(i64::from(i32::from_be_bytes(
                    b.try_into().unwrap(),
                ))))
            }
            INT_64 => {
                let b = self.take(8)?;
                Ok(BoltValue::Int(i64::from_be_bytes(b.try_into().unwrap())))
            }
            BYTES_8 => self.unpack_bytes(1),
            BYTES_16 => self.unpack_bytes(2),
            BYTES_32 => self.unpack_bytes(4),
            STRING_8 => sized!(1, unpack_string),
            STRING_16 => sized!(2, unpack_string),
            STRING_32 => sized!(4, unpack_string),
            LIST_8 => sized!(1, unpack_list),
            LIST_16 => sized!(2, unpack_list),
            LIST_32 => sized!(4, unpack_list),
            MAP_8 => sized!(1, unpack_map),
            MAP_16 => sized!(2, unpack_map),
            MAP_32 => sized!(4, unpack_map),
            STRUCT_8 => sized!(1, unpack_struct),
            STRUCT_16 => sized!(2, unpack_struct),
            STRUCT_32 => sized!(4, unpack_struct),
            other => Err(BoltError::Protocol(format!(
                "unknown PackStream marker: 0x{other:02x}"
            ))),
        }
    }

    fn unpack_string(&mut self, n: usize) -> Result<BoltValue> {
        let bytes = self.take(n)?;
        String::from_utf8(bytes.to_vec())
            .map(BoltValue::String)
            .map_err(|e| BoltError::Protocol(format!("invalid UTF-8 string: {e}")))
    }

    fn unpack_bytes(&mut self, width: usize) -> Result<BoltValue> {
        let n = self.size(width)?;
        Ok(BoltValue::Bytes(self.take(n)?.to_vec()))
    }

    /// Remaining input bytes; caps preallocation from wire-claimed counts.
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Decode `n` consecutive values.
    fn unpack_n(&mut self, n: usize) -> Result<Vec<BoltValue>> {
        let mut items = Vec::with_capacity(n.min(self.remaining()));
        for _ in 0..n {
            items.push(self.unpack()?);
        }
        Ok(items)
    }

    fn unpack_list(&mut self, n: usize) -> Result<BoltValue> {
        Ok(BoltValue::List(self.unpack_n(n)?))
    }

    fn unpack_map(&mut self, n: usize) -> Result<BoltValue> {
        let mut map = HashMap::with_capacity(n.min(self.remaining() / 2));
        for _ in 0..n {
            let key = match self.unpack()? {
                BoltValue::String(s) => s,
                other => {
                    return Err(BoltError::Protocol(format!(
                        "map key not a string: {other:?}"
                    )));
                }
            };
            map.insert(key, self.unpack()?);
        }
        Ok(BoltValue::Map(map))
    }

    fn unpack_struct(&mut self, n: usize) -> Result<BoltValue> {
        let signature = self.u8()?;
        Ok(BoltValue::Structure {
            signature,
            fields: self.unpack_n(n)?,
        })
    }
}

#[cfg(test)]
mod tests {
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
            fields: vec![
                BoltValue::Int(42),
                BoltValue::List(vec![BoltValue::String("Person".into())]),
            ],
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
}

#[cfg(test)]
mod fuzz_smoke {
    use super::*;

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
        map.insert(
            "k".to_string(),
            BoltValue::List(vec![BoltValue::Int(1); 20]),
        );
        pack(
            &BoltValue::Structure {
                signature: 0x70,
                fields: vec![BoltValue::Map(map)],
            },
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
