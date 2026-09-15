//! serde <-> [`BoltValue`] conversion (feature `serde`).
//!
//! `to_value` / `from_value` / `params` / `QueryResult::rows_as`.

use std::collections::HashMap;
use std::fmt;

use serde::de::{self, DeserializeOwned, IntoDeserializer};
use serde::ser::{self, Serialize};

use crate::connection::QueryResult;
use crate::error::BoltError;
use crate::value::BoltValue;

#[derive(Debug)]
pub struct ConvertError(String);

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ConvertError {}
impl ser::Error for ConvertError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self(msg.to_string())
    }
}
impl de::Error for ConvertError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self(msg.to_string())
    }
}
impl From<ConvertError> for BoltError {
    fn from(e: ConvertError) -> Self {
        BoltError::Protocol(format!("serde: {e}"))
    }
}

type Result<T, E = ConvertError> = std::result::Result<T, E>;

/// Serialize anything into a [`BoltValue`].
pub fn to_value<T: Serialize>(value: &T) -> Result<BoltValue> {
    value.serialize(ValueSerializer)
}

/// Serialize a struct/map into query parameters.
pub fn params<T: Serialize>(value: &T) -> Result<HashMap<String, BoltValue>> {
    match to_value(value)? {
        BoltValue::Map(m) => Ok(m),
        other => Err(ser::Error::custom(format!(
            "parameters must be a map, got {other:?}"
        ))),
    }
}

/// Deserialize a [`BoltValue`] into any `DeserializeOwned`.
pub fn from_value<T: DeserializeOwned>(value: BoltValue) -> Result<T> {
    T::deserialize(value)
}

impl QueryResult {
    /// Deserialize every row into `T` (fields matched by column name).
    pub fn rows_as<T: DeserializeOwned>(&self) -> Result<Vec<T>, BoltError> {
        self.rows_as_maps()
            .into_iter()
            .map(|row| from_value(BoltValue::Map(row)).map_err(Into::into))
            .collect()
    }
}

struct ValueSerializer;

macro_rules! ser_int {
    ($($method:ident: $ty:ty),+ $(,)?) => {
        $(fn $method(self, v: $ty) -> Result<BoltValue> {
            Ok(BoltValue::Int(i64::from(v)))
        })+
    };
}

impl ser::Serializer for ValueSerializer {
    type Ok = BoltValue;
    type Error = ConvertError;
    type SerializeSeq = SeqSer;
    type SerializeTuple = SeqSer;
    type SerializeTupleStruct = SeqSer;
    type SerializeTupleVariant = VariantSeqSer;
    type SerializeMap = MapSer;
    type SerializeStruct = MapSer;
    type SerializeStructVariant = VariantMapSer;

    ser_int!(
        serialize_i8: i8, serialize_i16: i16, serialize_i32: i32, serialize_i64: i64,
        serialize_u8: u8, serialize_u16: u16, serialize_u32: u32,
    );

    fn serialize_bool(self, v: bool) -> Result<BoltValue> {
        Ok(BoltValue::Bool(v))
    }

    fn serialize_u64(self, v: u64) -> Result<BoltValue> {
        i64::try_from(v)
            .map(BoltValue::Int)
            .map_err(|_| ser::Error::custom("u64 out of i64 range"))
    }

    fn serialize_f32(self, v: f32) -> Result<BoltValue> {
        Ok(BoltValue::Float(f64::from(v)))
    }

    fn serialize_f64(self, v: f64) -> Result<BoltValue> {
        Ok(BoltValue::Float(v))
    }

    fn serialize_char(self, v: char) -> Result<BoltValue> {
        Ok(BoltValue::from(v.to_string()))
    }

    fn serialize_str(self, v: &str) -> Result<BoltValue> {
        Ok(BoltValue::from(v.to_string()))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<BoltValue> {
        Ok(BoltValue::Bytes(v.to_vec().into()))
    }

    fn serialize_none(self) -> Result<BoltValue> {
        Ok(BoltValue::Null)
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<BoltValue> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<BoltValue> {
        Ok(BoltValue::Null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<BoltValue> {
        Ok(BoltValue::Null)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<BoltValue> {
        Ok(BoltValue::from(variant))
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<BoltValue> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<BoltValue> {
        let mut map = HashMap::new();
        map.insert(variant.to_string(), value.serialize(ValueSerializer)?);
        Ok(BoltValue::Map(map))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<SeqSer> {
        Ok(SeqSer {
            items: Vec::with_capacity(len.unwrap_or(0)),
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<SeqSer> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<SeqSer> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<VariantSeqSer> {
        Ok(VariantSeqSer {
            variant,
            items: Vec::with_capacity(len),
        })
    }

    fn serialize_map(self, len: Option<usize>) -> Result<MapSer> {
        Ok(MapSer {
            map: HashMap::with_capacity(len.unwrap_or(0)),
            key: None,
        })
    }

    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<MapSer> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<VariantMapSer> {
        Ok(VariantMapSer {
            variant,
            map: HashMap::with_capacity(len),
        })
    }
}

struct SeqSer {
    items: Vec<BoltValue>,
}

impl ser::SerializeSeq for SeqSer {
    type Ok = BoltValue;
    type Error = ConvertError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        self.items.push(value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<BoltValue> {
        Ok(BoltValue::List(self.items))
    }
}

impl ser::SerializeTuple for SeqSer {
    type Ok = BoltValue;
    type Error = ConvertError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<BoltValue> {
        ser::SerializeSeq::end(self)
    }
}

impl ser::SerializeTupleStruct for SeqSer {
    type Ok = BoltValue;
    type Error = ConvertError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<BoltValue> {
        ser::SerializeSeq::end(self)
    }
}

struct VariantSeqSer {
    variant: &'static str,
    items: Vec<BoltValue>,
}

impl ser::SerializeTupleVariant for VariantSeqSer {
    type Ok = BoltValue;
    type Error = ConvertError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        self.items.push(value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<BoltValue> {
        let mut map = HashMap::new();
        map.insert(self.variant.to_string(), BoltValue::List(self.items));
        Ok(BoltValue::Map(map))
    }
}

struct MapSer {
    map: HashMap<String, BoltValue>,
    key: Option<String>,
}

impl ser::SerializeMap for MapSer {
    type Ok = BoltValue;
    type Error = ConvertError;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<()> {
        match key.serialize(ValueSerializer)? {
            BoltValue::String(s) => {
                self.key = Some(s.into_owned());
                Ok(())
            }
            other => Err(ser::Error::custom(format!(
                "map key must be a string, got {other:?}"
            ))),
        }
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        let key = self
            .key
            .take()
            .ok_or_else(|| ser::Error::custom("value before key"))?;
        self.map.insert(key, value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<BoltValue> {
        Ok(BoltValue::Map(self.map))
    }
}

impl ser::SerializeStruct for MapSer {
    type Ok = BoltValue;
    type Error = ConvertError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        self.map
            .insert(key.to_string(), value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<BoltValue> {
        Ok(BoltValue::Map(self.map))
    }
}

struct VariantMapSer {
    variant: &'static str,
    map: HashMap<String, BoltValue>,
}

impl ser::SerializeStructVariant for VariantMapSer {
    type Ok = BoltValue;
    type Error = ConvertError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        self.map
            .insert(key.to_string(), value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<BoltValue> {
        let mut outer = HashMap::new();
        outer.insert(self.variant.to_string(), BoltValue::Map(self.map));
        Ok(BoltValue::Map(outer))
    }
}

impl<'de> de::Deserializer<'de> for BoltValue {
    type Error = ConvertError;

    fn deserialize_any<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self {
            BoltValue::Null => visitor.visit_unit(),
            BoltValue::Bool(b) => visitor.visit_bool(b),
            BoltValue::Int(i) => visitor.visit_i64(i),
            BoltValue::Float(f) => visitor.visit_f64(f),
            BoltValue::String(s) => visitor.visit_string(s.into_owned()),
            BoltValue::Bytes(b) => visitor.visit_byte_buf(b.into_owned()),
            BoltValue::List(items) => {
                visitor.visit_seq(de::value::SeqDeserializer::new(items.into_iter()))
            }
            BoltValue::Map(map) => {
                visitor.visit_map(de::value::MapDeserializer::new(map.into_iter()))
            }
            BoltValue::Structure { signature, .. } => Err(de::Error::custom(format!(
                "cannot deserialize graph structure 0x{signature:02x}; keep the field as BoltValue"
            ))),
        }
    }

    fn deserialize_option<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self {
            BoltValue::Null => visitor.visit_none(),
            other => visitor.visit_some(other),
        }
    }

    fn deserialize_newtype_struct<V: de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: de::Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        match self {
            BoltValue::String(s) => visitor.visit_enum(s.into_owned().into_deserializer()),
            BoltValue::Map(map) if map.len() == 1 => {
                visitor.visit_enum(de::value::MapAccessDeserializer::new(
                    de::value::MapDeserializer::new(map.into_iter()),
                ))
            }
            other => Err(de::Error::custom(format!(
                "cannot deserialize enum from {other:?}"
            ))),
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple tuple_struct map struct
        identifier ignored_any
    }
}

impl IntoDeserializer<'_, ConvertError> for BoltValue {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

#[cfg(test)]
mod test;
