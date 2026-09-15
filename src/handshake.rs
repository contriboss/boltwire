//! Handshake: magic preamble + version negotiation. Bolt 5.2-5.8 only.

/// Bolt magic preamble `0x6060B017`.
pub const MAGIC: [u8; 4] = [0x60, 0x60, 0xB0, 0x17];

/// A proposed/agreed Bolt version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

impl Version {
    #[must_use]
    pub const fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// Encode as the 4-byte handshake form `[0, range, minor, major]`;
    /// `range` accepts `minor - range ..= minor`.
    #[must_use]
    pub const fn encode_range(self, range: u8) -> [u8; 4] {
        [0, range, self.minor, self.major]
    }

    /// Decode the server's 4-byte agreed-version reply.
    #[must_use]
    pub const fn decode(bytes: [u8; 4]) -> Self {
        Self {
            major: bytes[3],
            minor: bytes[2],
        }
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.major == 0 && self.minor == 0
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

pub const MAX: Version = Version::new(5, 8);
pub const MIN: Version = Version::new(5, 2);
pub const SUPPORTED_RANGE: &str = "5.2-5.8";

/// Whether an agreed version falls in our window.
#[must_use]
pub const fn supported(v: Version) -> bool {
    v.major == MAX.major && v.minor >= MIN.minor && v.minor <= MAX.minor
}

/// 20-byte handshake: magic + proposals. Slot 0 = 5.2-5.8 range,
/// slot 1 = plain 5.2 for servers that ignore range bytes.
#[must_use]
pub fn client_hello() -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&MAGIC);
    out[4..8].copy_from_slice(&MAX.encode_range(MAX.minor - MIN.minor));
    out[8..12].copy_from_slice(&MIN.encode_range(0));
    out
}

#[cfg(test)]
mod test;
