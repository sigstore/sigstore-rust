//! The `root` role and the role-key bindings it carries.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::glob::glob_match;
use crate::key::Key;
use crate::metadata::Role;

/// The set of authorized keys and signature threshold for a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleKeys {
    /// Declared IDs of the keys authorized to sign for this role.
    pub keyids: Vec<String>,
    /// The number of distinct valid signatures required.
    pub threshold: usize,
    /// Producer-specific extras (e.g. `x-tuf-on-ci-*`), preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// The TUF `root` role: the trust anchor that delegates to all other roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    /// Always `"root"`.
    #[serde(rename = "_type")]
    pub type_: String,
    /// The TUF spec version this metadata targets.
    pub spec_version: String,
    /// Monotonically increasing version number.
    pub version: u64,
    /// Expiry timestamp (RFC 3339).
    pub expires: String,
    /// Whether the repository uses consistent snapshots (version-prefixed
    /// metadata/target file names).
    #[serde(default)]
    pub consistent_snapshot: bool,
    /// All keys referenced by any role, indexed by declared key ID.
    pub keys: BTreeMap<String, Key>,
    /// Role → authorized keys/threshold (`root`, `timestamp`, `snapshot`,
    /// `targets`).
    pub roles: BTreeMap<String, RoleKeys>,
    /// Producer-specific extras, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Root {
    /// Look up the key/threshold binding for a named role.
    pub fn role(&self, name: &str) -> Option<&RoleKeys> {
        self.roles.get(name)
    }
}

impl Role for Root {
    const TYPE: &'static str = "root";

    fn version(&self) -> u64 {
        self.version
    }

    fn expires(&self) -> &str {
        &self.expires
    }
}

/// A delegated targets role (the `roles` entries inside a `delegations` block).
///
/// Captured so targets delegation can be implemented without a metadata-model
/// change; the delegation *walk* itself is not wired up yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedRole {
    /// The delegated role's name.
    pub name: String,
    /// Declared key IDs authorized for the delegated role.
    pub keyids: Vec<String>,
    /// Required signature threshold.
    pub threshold: usize,
    /// Whether this delegation terminates the search.
    #[serde(default)]
    pub terminating: bool,
    /// Glob path patterns this role is authorized for.
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    /// Hash-prefix bins this role is authorized for.
    #[serde(default)]
    pub path_hash_prefixes: Option<Vec<String>>,
    /// Producer-specific extras, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl DelegatedRole {
    /// The key/threshold binding this delegated role represents.
    pub fn role_keys(&self) -> RoleKeys {
        RoleKeys {
            keyids: self.keyids.clone(),
            threshold: self.threshold,
            extra: BTreeMap::new(),
        }
    }

    /// Whether this delegated role is authorized for `target_path`.
    ///
    /// A role authorizes a path if it matches one of its `path_hash_prefixes`
    /// (the SHA-256 hex of the target path begins with the prefix) or one of its
    /// shell-style `paths` globs. A role with neither field authorizes nothing.
    pub fn matches_path(&self, target_path: &str) -> bool {
        if let Some(prefixes) = &self.path_hash_prefixes {
            let hash = hex::encode(sigstore_crypto::sha256(target_path.as_bytes()).as_bytes());
            return prefixes.iter().any(|p| hash.starts_with(p.as_str()));
        }
        if let Some(paths) = &self.paths {
            return paths.iter().any(|pat| glob_match(pat, target_path));
        }
        false
    }
}

/// A `delegations` block within a targets metadata file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegations {
    /// Keys referenced by the delegated roles, indexed by declared key ID.
    pub keys: BTreeMap<String, Key>,
    /// The ordered list of delegated roles.
    #[serde(default)]
    pub roles: Vec<DelegatedRole>,
    /// Producer-specific extras, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
