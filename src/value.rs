//! The Bolt/PackStream value model.

use std::borrow::Cow;
use std::collections::HashMap;

/// `PackStream` structure signatures for graph/temporal types carried in RECORDs.
pub mod sig {
    pub const NODE: u8 = 0x4E; // 'N'
    pub const RELATIONSHIP: u8 = 0x52; // 'R'
    pub const UNBOUND_RELATIONSHIP: u8 = 0x72; // 'r'
    pub const PATH: u8 = 0x50; // 'P'
    pub const DATE: u8 = 0x44; // 'D'
    pub const DURATION: u8 = 0x45; // 'E'
    pub const POINT_2D: u8 = 0x58; // 'X'
    pub const POINT_3D: u8 = 0x59; // 'Y'
    pub const LOCAL_TIME: u8 = 0x74; // 't'
    pub const LOCAL_DATETIME: u8 = 0x64; // 'd'
    pub const DATETIME_ZONED: u8 = 0x49; // 'I' (Bolt 5+)
}

#[derive(Debug, Clone, PartialEq)]
pub enum BoltValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(Cow<'static, str>),
    Bytes(Cow<'static, [u8]>),
    List(Vec<BoltValue>),
    Map(HashMap<String, BoltValue>),
    Structure { signature: u8, fields: Vec<BoltValue> },
}

/// Generate a `Option`-returning accessor that matches one `BoltValue` variant.
macro_rules! accessor {
    ($name:ident -> $ret:ty : $variant:ident($bind:pat) => $out:expr) => {
        #[must_use]
        pub fn $name(&self) -> Option<$ret> {
            match self {
                BoltValue::$variant($bind) => Some($out),
                _ => None,
            }
        }
    };
}

impl BoltValue {
    accessor!(as_str -> &str : String(s) => s.as_ref());
    accessor!(as_int -> i64 : Int(i) => *i);
    accessor!(as_bool -> bool : Bool(b) => *b);
    accessor!(as_map -> &HashMap<String, BoltValue> : Map(m) => m);
    accessor!(as_list -> &[BoltValue] : List(l) => l.as_slice());

    /// Look up a key in a `Map` value, returning `None` for non-maps or misses.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&BoltValue> {
        self.as_map().and_then(|m| m.get(key))
    }

    /// String items of a `List` value; empty for non-lists.
    #[must_use]
    pub fn as_strings(&self) -> Vec<String> {
        self.as_list()
            .map(|l| l.iter().filter_map(|v| v.as_str().map(ToString::to_string)).collect())
            .unwrap_or_default()
    }
}

/// Ergonomic constructors for building parameter/metadata maps.
impl From<&'static str> for BoltValue {
    fn from(s: &'static str) -> Self {
        BoltValue::String(Cow::Borrowed(s))
    }
}
impl From<String> for BoltValue {
    fn from(s: String) -> Self {
        BoltValue::String(Cow::Owned(s))
    }
}
impl From<Cow<'static, str>> for BoltValue {
    fn from(s: Cow<'static, str>) -> Self {
        BoltValue::String(s)
    }
}
impl From<i64> for BoltValue {
    fn from(i: i64) -> Self {
        BoltValue::Int(i)
    }
}
impl From<i32> for BoltValue {
    fn from(i: i32) -> Self {
        BoltValue::Int(i64::from(i))
    }
}
impl From<f64> for BoltValue {
    fn from(f: f64) -> Self {
        BoltValue::Float(f)
    }
}
impl From<bool> for BoltValue {
    fn from(b: bool) -> Self {
        BoltValue::Bool(b)
    }
}
impl<T: Into<BoltValue>> From<Vec<T>> for BoltValue {
    fn from(v: Vec<T>) -> Self {
        BoltValue::List(v.into_iter().map(Into::into).collect())
    }
}
