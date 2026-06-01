//! The `timestamp` and `snapshot` roles.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::metadata::Role;

/// A reference to another metadata file, as recorded by a parent role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaFile {
    /// The referenced file's version number.
    pub version: u64,
    /// The expected length in bytes, if pinned.
    #[serde(default)]
    pub length: Option<u64>,
    /// The expected hashes (algorithm → hex digest), if pinned.
    #[serde(default)]
    pub hashes: Option<BTreeMap<String, String>>,
    /// Producer-specific extras, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// The TUF `timestamp` role: pins the current `snapshot` version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp {
    /// Always `"timestamp"`.
    #[serde(rename = "_type")]
    pub type_: String,
    /// The TUF spec version this metadata targets.
    pub spec_version: String,
    /// Monotonically increasing version number.
    pub version: u64,
    /// Expiry timestamp (RFC 3339).
    pub expires: String,
    /// A single entry, `"snapshot.json"`, pinning the snapshot.
    pub meta: BTreeMap<String, MetaFile>,
    /// Producer-specific extras, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Timestamp {
    /// The pinned `snapshot.json` reference, if present.
    pub fn snapshot_meta(&self) -> Option<&MetaFile> {
        self.meta.get("snapshot.json")
    }
}

impl Role for Timestamp {
    const TYPE: &'static str = "timestamp";

    fn version(&self) -> u64 {
        self.version
    }

    fn expires(&self) -> &str {
        &self.expires
    }
}

/// The TUF `snapshot` role: pins the version of every targets metadata file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Always `"snapshot"`.
    #[serde(rename = "_type")]
    pub type_: String,
    /// The TUF spec version this metadata targets.
    pub spec_version: String,
    /// Monotonically increasing version number.
    pub version: u64,
    /// Expiry timestamp (RFC 3339).
    pub expires: String,
    /// Targets metadata file name → pinned reference.
    pub meta: BTreeMap<String, MetaFile>,
    /// Producer-specific extras, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Role for Snapshot {
    const TYPE: &'static str = "snapshot";

    fn version(&self) -> u64 {
        self.version
    }

    fn expires(&self) -> &str {
        &self.expires
    }
}
