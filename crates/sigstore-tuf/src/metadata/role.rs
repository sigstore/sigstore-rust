//! The `root` role and the role-key bindings it carries.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
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
/// The delegation walk that consumes these lives in
/// [`Updater::get_targetinfo`](crate::client::Updater::get_targetinfo).
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
    ///
    /// Patterns are evaluated using TUF's shell-style path-pattern grammar:
    /// `*`, `?`, and bracket expressions never match a path separator (`/`).
    /// Every `*` is interpreted independently, so adjacent stars do not acquire
    /// the recursive-glob semantics that some glob libraries assign to `**`.
    /// A malformed pattern is a hard error rather than a silent non-match, so a
    /// repository we cannot correctly evaluate is rejected instead of having a
    /// delegation quietly ignored.
    pub fn matches_path(&self, target_path: &str) -> Result<bool> {
        if let Some(prefixes) = &self.path_hash_prefixes {
            let hash = hex::encode(sigstore_crypto::sha256(target_path.as_bytes()).as_bytes());
            return Ok(prefixes.iter().any(|p| hash.starts_with(p.as_str())));
        }
        if let Some(paths) = &self.paths {
            for pattern in paths {
                let tokens = parse_path_pattern(pattern).map_err(|e| {
                    Error::Malformed(format!(
                        "role {:?} has invalid delegation path pattern {pattern:?}: {e}",
                        self.name
                    ))
                })?;
                if path_pattern_matches(&tokens, target_path) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PathPatternToken {
    Literal(char),
    AnySequence,
    AnyCharacter,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

/// Parse the shell-style path-pattern subset defined by TUF. Parsing this
/// locally avoids library-specific extensions such as recursive `**` globs.
fn parse_path_pattern(pattern: &str) -> std::result::Result<Vec<PathPatternToken>, String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '*' => tokens.push(PathPatternToken::AnySequence),
            '?' => tokens.push(PathPatternToken::AnyCharacter),
            '[' => {
                let close = chars[i + 1..]
                    .iter()
                    .position(|c| *c == ']')
                    .map(|offset| i + 1 + offset)
                    .ok_or_else(|| "unclosed character class".to_string())?;
                let mut contents = &chars[i + 1..close];
                let negated = contents.first() == Some(&'!');
                if negated {
                    contents = &contents[1..];
                }
                if contents.is_empty() {
                    return Err("empty character class".to_string());
                }

                let mut ranges = Vec::new();
                let mut j = 0;
                while j < contents.len() {
                    if j + 2 < contents.len() && contents[j + 1] == '-' {
                        let start = contents[j];
                        let end = contents[j + 2];
                        if start > end {
                            return Err(format!("invalid character range {start}-{end}"));
                        }
                        ranges.push((start, end));
                        j += 3;
                    } else {
                        ranges.push((contents[j], contents[j]));
                        j += 1;
                    }
                }
                tokens.push(PathPatternToken::Class { negated, ranges });
                i = close;
            }
            literal => tokens.push(PathPatternToken::Literal(literal)),
        }
        i += 1;
    }
    Ok(tokens)
}

fn path_pattern_matches(tokens: &[PathPatternToken], target_path: &str) -> bool {
    let target: Vec<char> = target_path.chars().collect();
    let mut matched = vec![false; target.len() + 1];
    matched[0] = true;

    for token in tokens {
        let mut next = vec![false; target.len() + 1];
        match token {
            PathPatternToken::AnySequence => {
                next[0] = matched[0];
                for i in 1..=target.len() {
                    // Match zero characters, or extend this same star by one
                    // non-separator character.
                    next[i] = matched[i] || (target[i - 1] != '/' && next[i - 1]);
                }
            }
            PathPatternToken::Literal(expected) => {
                for i in 1..=target.len() {
                    next[i] = matched[i - 1] && target[i - 1] == *expected;
                }
            }
            PathPatternToken::AnyCharacter => {
                for i in 1..=target.len() {
                    next[i] = matched[i - 1] && target[i - 1] != '/';
                }
            }
            PathPatternToken::Class { negated, ranges } => {
                for i in 1..=target.len() {
                    let actual = target[i - 1];
                    let contained = ranges
                        .iter()
                        .any(|(start, end)| *start <= actual && actual <= *end);
                    next[i] = matched[i - 1] && actual != '/' && contained != *negated;
                }
            }
        }
        matched = next;
    }

    matched[target.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(value: serde_json::Value) -> DelegatedRole {
        serde_json::from_value(value).unwrap()
    }

    fn with_paths(paths: serde_json::Value) -> DelegatedRole {
        role(serde_json::json!({
            "name": "d", "keyids": [], "threshold": 1, "paths": paths
        }))
    }

    #[test]
    fn star_does_not_cross_path_separator() {
        // Shell-glob semantics per the TUF spec: `*` matches within a path
        // segment but not across `/`.
        let p = with_paths(serde_json::json!(["*.json"]));
        assert!(p.matches_path("trusted_root.json").unwrap());
        assert!(!p.matches_path("nested/dir/trusted_root.json").unwrap());
        assert!(!p.matches_path("trusted_root.txt").unwrap());

        // `registry/*` matches one segment under registry/, not deeper.
        let r = with_paths(serde_json::json!(["registry/*"]));
        assert!(r.matches_path("registry/index.json").unwrap());
        assert!(!r.matches_path("registry/a/b/index.json").unwrap());

        // The spec example: a star per segment matches the corresponding depth.
        let nested = with_paths(serde_json::json!(["releases/*/*"]));
        assert!(nested.matches_path("releases/x/x_v1").unwrap());
        assert!(!nested.matches_path("releases/x").unwrap());
        assert!(!nested.matches_path("releases/x/y/z").unwrap());

        // Adjacent stars are still independent `*` tokens in TUF: neither may
        // match `/`, so `**` must not acquire recursive-glob semantics.
        let adjacent = with_paths(serde_json::json!(["releases/**"]));
        assert!(adjacent.matches_path("releases/package").unwrap());
        assert!(!adjacent.matches_path("releases/stable/package").unwrap());
    }

    #[test]
    fn supports_character_classes_and_single_char() {
        let r = with_paths(serde_json::json!(["foo-[0-9].tgz"]));
        assert!(r.matches_path("foo-2.tgz").unwrap());
        assert!(!r.matches_path("foo-a.tgz").unwrap());
        let q = with_paths(serde_json::json!(["foo-?.tgz"]));
        assert!(q.matches_path("foo-x.tgz").unwrap());
        assert!(!q.matches_path("foo-xy.tgz").unwrap());
    }

    #[test]
    fn path_hash_prefixes_match_on_sha256_of_path() {
        let target = "some/target/path";
        let hash = hex::encode(sigstore_crypto::sha256(target.as_bytes()).as_bytes());
        let prefix = &hash[..4];
        let r = role(serde_json::json!({
            "name": "bin", "keyids": [], "threshold": 1,
            "path_hash_prefixes": [prefix],
        }));
        assert!(r.matches_path(target).unwrap());
        assert!(!r
            .matches_path("a/totally/different/path/that/wont/collide")
            .unwrap());
    }

    #[test]
    fn invalid_pattern_is_a_hard_error() {
        // An unparseable glob must fail closed, not silently fail to match.
        let r = with_paths(serde_json::json!(["a[b"]));
        assert!(r.matches_path("anything").is_err());
    }

    #[test]
    fn no_paths_and_no_prefixes_authorizes_nothing() {
        let r = role(serde_json::json!({ "name": "d", "keyids": [], "threshold": 1 }));
        assert!(!r.matches_path("anything").unwrap());
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
