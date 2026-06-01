//! The `targets` role.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::metadata::role::Delegations;
use crate::metadata::Role;

/// A single target file's metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetFile {
    /// The target's length in bytes.
    pub length: u64,
    /// The target's hashes (algorithm → hex digest).
    pub hashes: BTreeMap<String, String>,
    /// Opaque, application-specific metadata attached to the target.
    #[serde(default)]
    pub custom: Option<Value>,
    /// Producer-specific extras, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// The TUF `targets` role: the inventory of distributable target files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Targets {
    /// Always `"targets"`.
    #[serde(rename = "_type")]
    pub type_: String,
    /// The TUF spec version this metadata targets.
    pub spec_version: String,
    /// Monotonically increasing version number.
    pub version: u64,
    /// Expiry timestamp (RFC 3339).
    pub expires: String,
    /// Target path → target metadata.
    pub targets: BTreeMap<String, TargetFile>,
    /// Optional delegations to other targets roles.
    #[serde(default)]
    pub delegations: Option<Delegations>,
    /// Producer-specific extras, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Targets {
    /// Look up a target by its path.
    pub fn target(&self, path: &str) -> Option<&TargetFile> {
        self.targets.get(path)
    }
}

impl Role for Targets {
    const TYPE: &'static str = "targets";

    fn version(&self) -> u64 {
        self.version
    }

    fn expires(&self) -> &str {
        &self.expires
    }
}
