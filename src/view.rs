//! Zero-copy views over graph/temporal [`BoltValue::Structure`]s.
//! The wire stays raw; these interpret it on demand.

use std::collections::HashMap;

use crate::value::{BoltValue, sig};

#[derive(Debug, Clone, Copy)]
pub struct NodeRef<'a> {
    pub id: i64,
    pub labels: &'a [BoltValue],
    pub properties: &'a HashMap<String, BoltValue>,
    pub element_id: Option<&'a str>,
}

impl<'a> NodeRef<'a> {
    #[must_use]
    pub fn label_strs(&self) -> Vec<&'a str> {
        self.labels.iter().filter_map(BoltValue::as_str).collect()
    }

    #[must_use]
    pub fn prop(&self, key: &str) -> Option<&'a BoltValue> {
        self.properties.get(key)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RelationshipRef<'a> {
    pub id: i64,
    pub start_id: i64,
    pub end_id: i64,
    pub type_: &'a str,
    pub properties: &'a HashMap<String, BoltValue>,
    pub element_id: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub struct UnboundRelationshipRef<'a> {
    pub id: i64,
    pub type_: &'a str,
    pub properties: &'a HashMap<String, BoltValue>,
}

#[derive(Debug, Clone)]
pub struct PathRef<'a> {
    pub nodes: Vec<NodeRef<'a>>,
    pub relationships: Vec<UnboundRelationshipRef<'a>>,
    pub indices: Vec<i64>,
}

/// `[months, days, seconds, nanoseconds]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurationRef {
    pub months: i64,
    pub days: i64,
    pub seconds: i64,
    pub nanoseconds: i64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PointRef {
    pub srid: i64,
    pub x: f64,
    pub y: f64,
    /// Only for 3D points.
    pub z: Option<f64>,
}

fn fields_of(value: &BoltValue, want: u8) -> Option<&[BoltValue]> {
    match value {
        BoltValue::Structure { signature, fields } if *signature == want => Some(fields),
        _ => None,
    }
}

fn int(fields: &[BoltValue], i: usize) -> Option<i64> {
    fields.get(i).and_then(BoltValue::as_int)
}

#[allow(clippy::cast_precision_loss)] // servers send coordinates as Int when whole
fn float(fields: &[BoltValue], i: usize) -> Option<f64> {
    match fields.get(i)? {
        BoltValue::Float(f) => Some(*f),
        BoltValue::Int(n) => Some(*n as f64),
        _ => None,
    }
}

fn map(fields: &[BoltValue], i: usize) -> Option<&HashMap<String, BoltValue>> {
    fields.get(i).and_then(BoltValue::as_map)
}

fn list_at<'a, T>(
    fields: &'a [BoltValue],
    i: usize,
    view: impl Fn(&'a BoltValue) -> Option<T>,
) -> Option<Vec<T>> {
    fields.get(i).and_then(BoltValue::as_list)?.iter().map(view).collect()
}

impl BoltValue {
    #[must_use]
    pub fn as_node(&self) -> Option<NodeRef<'_>> {
        let f = fields_of(self, sig::NODE)?;
        Some(NodeRef {
            id: int(f, 0)?,
            labels: f.get(1).and_then(BoltValue::as_list)?,
            properties: map(f, 2)?,
            element_id: f.get(3).and_then(BoltValue::as_str),
        })
    }

    #[must_use]
    pub fn as_relationship(&self) -> Option<RelationshipRef<'_>> {
        let f = fields_of(self, sig::RELATIONSHIP)?;
        Some(RelationshipRef {
            id: int(f, 0)?,
            start_id: int(f, 1)?,
            end_id: int(f, 2)?,
            type_: f.get(3).and_then(BoltValue::as_str)?,
            properties: map(f, 4)?,
            element_id: f.get(5).and_then(BoltValue::as_str),
        })
    }

    #[must_use]
    pub fn as_unbound_relationship(&self) -> Option<UnboundRelationshipRef<'_>> {
        let f = fields_of(self, sig::UNBOUND_RELATIONSHIP)?;
        Some(UnboundRelationshipRef {
            id: int(f, 0)?,
            type_: f.get(1).and_then(BoltValue::as_str)?,
            properties: map(f, 2)?,
        })
    }

    #[must_use]
    pub fn as_path(&self) -> Option<PathRef<'_>> {
        let f = fields_of(self, sig::PATH)?;
        Some(PathRef {
            nodes: list_at(f, 0, BoltValue::as_node)?,
            relationships: list_at(f, 1, BoltValue::as_unbound_relationship)?,
            indices: list_at(f, 2, BoltValue::as_int)?,
        })
    }

    /// Days since the Unix epoch.
    #[must_use]
    pub fn as_date_days(&self) -> Option<i64> {
        int(fields_of(self, sig::DATE)?, 0)
    }

    /// Nanoseconds since midnight.
    #[must_use]
    pub fn as_local_time_nanos(&self) -> Option<i64> {
        int(fields_of(self, sig::LOCAL_TIME)?, 0)
    }

    /// `(seconds, nanoseconds)` since the Unix epoch, no zone.
    #[must_use]
    pub fn as_local_datetime(&self) -> Option<(i64, i64)> {
        let f = fields_of(self, sig::LOCAL_DATETIME)?;
        Some((int(f, 0)?, int(f, 1)?))
    }

    /// `(seconds, nanoseconds, offset_seconds)` - Bolt 5 UTC datetime.
    #[must_use]
    pub fn as_datetime_offset(&self) -> Option<(i64, i64, i64)> {
        let f = fields_of(self, sig::DATETIME_ZONED)?;
        Some((int(f, 0)?, int(f, 1)?, int(f, 2)?))
    }

    #[must_use]
    pub fn as_duration(&self) -> Option<DurationRef> {
        let f = fields_of(self, sig::DURATION)?;
        Some(DurationRef {
            months: int(f, 0)?,
            days: int(f, 1)?,
            seconds: int(f, 2)?,
            nanoseconds: int(f, 3)?,
        })
    }

    #[must_use]
    pub fn as_point(&self) -> Option<PointRef> {
        if let Some(f) = fields_of(self, sig::POINT_2D) {
            return Some(PointRef { srid: int(f, 0)?, x: float(f, 1)?, y: float(f, 2)?, z: None });
        }
        let f = fields_of(self, sig::POINT_3D)?;
        Some(PointRef { srid: int(f, 0)?, x: float(f, 1)?, y: float(f, 2)?, z: Some(float(f, 3)?) })
    }
}

#[cfg(test)]
mod test;
