//! Cluster routing table.

use std::collections::HashMap;

use crate::error::{BoltError, Result};
use crate::value::BoltValue;

#[derive(Debug, Clone, Default)]
pub struct RoutingTable {
    pub ttl_seconds: i64,
    pub db: Option<String>,
    pub routers: Vec<String>,
    pub readers: Vec<String>,
    pub writers: Vec<String>,
}

impl RoutingTable {
    /// Parse the `rt` map out of a ROUTE SUCCESS response.
    pub fn from_meta(meta: &HashMap<String, BoltValue>) -> Result<Self> {
        let rt = meta
            .get("rt")
            .and_then(BoltValue::as_map)
            .ok_or_else(|| BoltError::Protocol("ROUTE response missing rt map".into()))?;

        let mut table = RoutingTable {
            ttl_seconds: rt.get("ttl").and_then(BoltValue::as_int).unwrap_or(0),
            db: rt.get("db").and_then(BoltValue::as_str).map(ToString::to_string),
            ..Default::default()
        };

        let servers = rt
            .get("servers")
            .and_then(BoltValue::as_list)
            .ok_or_else(|| BoltError::Protocol("ROUTE response missing servers".into()))?;

        for server in servers {
            let role = server.get("role").and_then(BoltValue::as_str).unwrap_or("");
            let addresses = server.get("addresses").map(BoltValue::as_strings).unwrap_or_default();
            match role {
                "ROUTE" => table.routers.extend(addresses),
                "READ" => table.readers.extend(addresses),
                "WRITE" => table.writers.extend(addresses),
                _ => {}
            }
        }
        Ok(table)
    }

    /// Drop a dead server from every role.
    pub fn remove(&mut self, addr: &str) {
        self.routers.retain(|a| a != addr);
        self.readers.retain(|a| a != addr);
        self.writers.retain(|a| a != addr);
    }
}

#[cfg(test)]
mod test;
