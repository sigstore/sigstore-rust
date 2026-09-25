//! Hex-encoded values used by the Rekor v1 API

use serde::{Deserialize, Serialize};
use sigstore_types::{Error, LogKeyId, Result, Sha256Hash};

/// Hex-encoded transparency log ID, as returned by the Rekor v1 API.
///
/// Bundles carry the same ID as a base64 [`LogKeyId`]; see
/// [`HexLogId::to_log_key_id`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HexLogId(String);

impl HexLogId {
    /// Wrap a hex string. The encoding is checked when the ID is decoded.
    pub fn new(s: impl Into<String>) -> Self {
        HexLogId(s.into())
    }

    /// Hex-encode raw log ID bytes.
    pub fn encode(bytes: &[u8]) -> Self {
        HexLogId(hex::encode(bytes))
    }

    /// Decode to raw bytes
    pub fn decode(&self) -> Result<Vec<u8>> {
        hex::decode(&self.0).map_err(|e| Error::InvalidEncoding(format!("invalid hex: {}", e)))
    }

    /// The same ID in the bundle's representation.
    pub fn to_log_key_id(&self) -> Result<LogKeyId> {
        Ok(LogKeyId::from_bytes(&self.decode()?))
    }

    /// The hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Take ownership of the hex string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for HexLogId {
    fn from(s: String) -> Self {
        HexLogId(s)
    }
}

impl AsRef<str> for HexLogId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for HexLogId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Hex-encoded hash value, as used in Rekor v1 entry bodies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HexHash(String);

impl HexHash {
    /// Wrap a hex string. The encoding is checked when the hash is decoded.
    pub fn new(s: impl Into<String>) -> Self {
        HexHash(s.into())
    }

    /// Hex-encode raw hash bytes.
    pub fn encode(bytes: &[u8]) -> Self {
        HexHash(hex::encode(bytes))
    }

    /// Decode to raw bytes
    pub fn decode(&self) -> Result<Vec<u8>> {
        hex::decode(&self.0).map_err(|e| Error::InvalidEncoding(format!("invalid hex: {}", e)))
    }

    /// Decode as a SHA-256 hash (validates the length).
    pub fn to_sha256(&self) -> Result<Sha256Hash> {
        Sha256Hash::from_hex(&self.0)
    }

    /// The hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Take ownership of the hex string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for HexHash {
    fn from(s: String) -> Self {
        HexHash(s)
    }
}

impl AsRef<str> for HexHash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for HexHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_log_id() {
        let bytes = vec![1, 2, 3, 4];
        let log_id = HexLogId::encode(&bytes);
        assert_eq!(log_id.as_str(), "01020304");
        assert_eq!(log_id.decode().unwrap(), bytes);
        assert_eq!(
            log_id.to_log_key_id().unwrap(),
            LogKeyId::from_bytes(&bytes)
        );
    }
}
