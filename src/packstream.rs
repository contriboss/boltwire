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
            pack_header(fields.len(), TINY_STRUCT, STRUCT_8, STRUCT_16, "struct", out)?;
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
        return Err(BoltError::Protocol(format!("{label} too large to pack ({size})")));
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
        let end =
            self.pos.checked_add(n).ok_or_else(|| BoltError::Protocol("length overflow".into()))?;
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
                Ok(BoltValue::Int(i64::from(i16::from_be_bytes(b.try_into().unwrap()))))
            }
            INT_32 => {
                let b = self.take(4)?;
                Ok(BoltValue::Int(i64::from(i32::from_be_bytes(b.try_into().unwrap()))))
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
            other => Err(BoltError::Protocol(format!("unknown PackStream marker: 0x{other:02x}"))),
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
                    return Err(BoltError::Protocol(format!("map key not a string: {other:?}")));
                }
            };
            map.insert(key, self.unpack()?);
        }
        Ok(BoltValue::Map(map))
    }

    fn unpack_struct(&mut self, n: usize) -> Result<BoltValue> {
        let signature = self.u8()?;
        Ok(BoltValue::Structure { signature, fields: self.unpack_n(n)? })
    }
}

#[cfg(test)]
mod test;
