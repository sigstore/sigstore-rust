//! The trusted metadata state machine.
//!
//! [`TrustedMetadataSet`] holds the metadata a client currently trusts and
//! enforces the TUF client workflow's verification rules as new metadata is fed
//! in: signature thresholds, version monotonicity (anti-rollback), expiry, and
//! cross-role integrity (length/hash) pinning. It performs **no I/O** — feeding
//! it bytes is the caller's job (see [`crate::client`]) — which keeps every
//! security check unit-testable against fixed inputs.
//!
//! The design mirrors `python-tuf`'s `TrustedMetadataSet` and `go-tuf`'s
//! trusted-metadata handling, including the rule that a pinned/bootstrap root is
//! trusted on first use and its declared key IDs are authoritative.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};
use crate::key::Key;
use crate::metadata::{MetaFile, Metadata, Role, RoleKeys, Root, Snapshot, Targets, Timestamp};

/// The set of currently-trusted TUF metadata.
#[derive(Debug, Clone)]
pub struct TrustedMetadataSet {
    root: Metadata<Root>,
    timestamp: Option<Metadata<Timestamp>>,
    snapshot: Option<Metadata<Snapshot>>,
    /// Top-level targets and any delegated targets, keyed by role name.
    targets: BTreeMap<String, Metadata<Targets>>,
}

impl TrustedMetadataSet {
    /// Bootstrap from a pinned root.
    ///
    /// The root is *trusted on first use*: it must be correctly self-signed
    /// (carry a `root`-role threshold of valid signatures over its own keys),
    /// but its declared key IDs are taken as authoritative and its expiry is not
    /// checked here (expiry is enforced once we move on to timestamp).
    pub fn from_root(bytes: &[u8]) -> Result<Self> {
        let root = Metadata::<Root>::from_slice(bytes)?;
        verify_root_self_signed(&root)?;
        Ok(Self {
            root,
            timestamp: None,
            snapshot: None,
            targets: BTreeMap::new(),
        })
    }

    /// The currently trusted root payload.
    pub fn root(&self) -> &Root {
        &self.root.signed
    }

    /// The currently trusted timestamp payload, if one has been loaded.
    pub fn timestamp(&self) -> Option<&Timestamp> {
        self.timestamp.as_ref().map(|m| &m.signed)
    }

    /// The currently trusted snapshot payload, if one has been loaded.
    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref().map(|m| &m.signed)
    }

    /// The trusted top-level targets payload, if one has been loaded.
    pub fn targets(&self) -> Option<&Targets> {
        self.targets.get("targets").map(|m| &m.signed)
    }

    /// Incorporate a candidate newer root.
    ///
    /// Enforces:
    /// * the new version is exactly `trusted + 1`, and
    /// * the new root is signed to threshold by **both** the currently trusted
    ///   root's `root` role **and** the new root's own `root` role.
    ///
    /// Intermediate root expiry is intentionally not checked, matching the TUF
    /// spec's root-chaining rules.
    pub fn update_root(&mut self, bytes: &[u8]) -> Result<()> {
        let new_root = Metadata::<Root>::from_slice(bytes)?;

        let trusted_version = self.root.signed.version;
        let new_version = new_root.signed.version;
        if new_version != trusted_version + 1 {
            return Err(Error::BadRootVersion {
                trusted: trusted_version,
                new: new_version,
            });
        }

        // Signed by the old root's authority...
        verify_with_root(&new_root, &self.root.signed, "root")?;
        // ...and self-consistent under the new root's authority.
        verify_root_self_signed(&new_root)?;

        self.root = new_root;
        // A new root may rotate keys; previously trusted lower roles must be
        // re-verified against it, so drop them.
        self.timestamp = None;
        self.snapshot = None;
        self.targets.clear();
        Ok(())
    }

    /// Assert that the trusted root has not expired as of `now`.
    ///
    /// Per the TUF workflow this is checked once root updating is complete,
    /// before consuming timestamp.
    pub fn check_root_expired(&self, now: jiff::Timestamp) -> Result<()> {
        ensure_not_expired(&self.root.signed, "root", now)
    }

    /// Incorporate a candidate timestamp.
    ///
    /// Verifies the `timestamp`-role signature threshold, rejects rollback of
    /// both the timestamp version and the snapshot version it pins, and checks
    /// expiry.
    pub fn update_timestamp(&mut self, bytes: &[u8], now: jiff::Timestamp) -> Result<()> {
        let new = Metadata::<Timestamp>::from_slice(bytes)?;
        verify_with_root(&new, &self.root.signed, "timestamp")?;

        if let Some(current) = &self.timestamp {
            if new.signed.version < current.signed.version {
                return Err(Error::Rollback {
                    role: "timestamp".to_string(),
                    trusted: current.signed.version,
                    new: new.signed.version,
                });
            }
            // The pinned snapshot version must not move backwards either.
            if let (Some(new_meta), Some(cur_meta)) =
                (new.signed.snapshot_meta(), current.signed.snapshot_meta())
            {
                if new_meta.version < cur_meta.version {
                    return Err(Error::Rollback {
                        role: "snapshot (via timestamp)".to_string(),
                        trusted: cur_meta.version,
                        new: new_meta.version,
                    });
                }
            }
        }

        ensure_not_expired(&new.signed, "timestamp", now)?;
        self.timestamp = Some(new);
        Ok(())
    }

    /// Incorporate a candidate snapshot.
    ///
    /// Requires a trusted timestamp first; checks the snapshot's length/hash and
    /// version against the timestamp pin, verifies the `snapshot`-role signature
    /// threshold, enforces no per-target rollback versus the trusted snapshot,
    /// and checks expiry.
    pub fn update_snapshot(&mut self, bytes: &[u8], now: jiff::Timestamp) -> Result<()> {
        let timestamp = self
            .timestamp
            .as_ref()
            .ok_or_else(|| Error::Malformed("cannot load snapshot before timestamp".to_string()))?;
        let pin = timestamp
            .signed
            .snapshot_meta()
            .ok_or_else(|| Error::Malformed("timestamp does not pin snapshot.json".to_string()))?;

        check_integrity(bytes, pin, "snapshot.json")?;

        let new = Metadata::<Snapshot>::from_slice(bytes)?;
        verify_with_root(&new, &self.root.signed, "snapshot")?;

        if new.signed.version != pin.version {
            return Err(Error::IntegrityMismatch(format!(
                "snapshot version {} does not match timestamp pin {}",
                new.signed.version, pin.version
            )));
        }

        // No targets metadata may be rolled back relative to the trusted snapshot.
        if let Some(current) = &self.snapshot {
            for (name, cur_meta) in &current.signed.meta {
                if let Some(new_meta) = new.signed.meta.get(name) {
                    if new_meta.version < cur_meta.version {
                        return Err(Error::Rollback {
                            role: format!("{name} (via snapshot)"),
                            trusted: cur_meta.version,
                            new: new_meta.version,
                        });
                    }
                }
            }
        }

        ensure_not_expired(&new.signed, "snapshot", now)?;
        self.snapshot = Some(new);
        // A new snapshot invalidates previously trusted targets.
        self.targets.clear();
        Ok(())
    }

    /// A trusted targets role by name (`"targets"` for the top level, or a
    /// delegated role name), if it has been loaded.
    pub fn targets_role(&self, name: &str) -> Option<&Targets> {
        self.targets.get(name).map(|m| &m.signed)
    }

    /// Incorporate the top-level `targets` metadata file.
    ///
    /// Requires a trusted snapshot first; checks length/hash/version against the
    /// snapshot pin, verifies the `targets`-role signature threshold **against
    /// the root**, and checks expiry.
    pub fn update_targets(&mut self, bytes: &[u8], now: jiff::Timestamp) -> Result<&Targets> {
        let new = self.verify_targets_pin(bytes, "targets")?;
        verify_with_root(&new, &self.root.signed, "targets")?;
        ensure_not_expired(&new.signed, "targets", now)?;
        self.targets.insert("targets".to_string(), new);
        Ok(&self.targets["targets"].signed)
    }

    /// Incorporate a delegated targets metadata file `role_name`, delegated by
    /// the already-trusted targets role `delegator_name`.
    ///
    /// The signature threshold is verified against the **delegator's**
    /// `delegations` block (its keys and the delegated role's keyids/threshold),
    /// not the root — this is what makes delegation a real trust hand-off.
    pub fn update_delegated_targets(
        &mut self,
        bytes: &[u8],
        role_name: &str,
        delegator_name: &str,
        now: jiff::Timestamp,
    ) -> Result<&Targets> {
        let (keys, role_keys) = self.delegation_authority(delegator_name, role_name)?;
        let new = self.verify_targets_pin(bytes, role_name)?;
        new.verify_threshold(&keys, &role_keys, role_name)?;
        ensure_not_expired(&new.signed, role_name, now)?;
        self.targets.insert(role_name.to_string(), new);
        Ok(&self.targets[role_name].signed)
    }

    /// Parse a targets file and check it against the snapshot pin (length, hash,
    /// and version), without verifying signatures (the caller decides whether
    /// the authority is the root or a delegator).
    fn verify_targets_pin(&self, bytes: &[u8], role_name: &str) -> Result<Metadata<Targets>> {
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| Error::Malformed("cannot load targets before snapshot".to_string()))?;
        let meta_name = format!("{role_name}.json");
        let pin = snapshot
            .signed
            .meta
            .get(&meta_name)
            .ok_or_else(|| Error::Malformed(format!("snapshot does not pin {meta_name}")))?;

        check_integrity(bytes, pin, &meta_name)?;

        let new = Metadata::<Targets>::from_slice(bytes)?;
        if new.signed.version != pin.version {
            return Err(Error::IntegrityMismatch(format!(
                "{meta_name} version {} does not match snapshot pin {}",
                new.signed.version, pin.version
            )));
        }
        Ok(new)
    }

    /// Resolve the keys and threshold that authorize `role_name`, as declared in
    /// the `delegations` block of the already-trusted `delegator_name`.
    fn delegation_authority(
        &self,
        delegator_name: &str,
        role_name: &str,
    ) -> Result<(BTreeMap<String, Key>, RoleKeys)> {
        let delegator = self
            .targets
            .get(delegator_name)
            .ok_or_else(|| Error::UnknownRole(delegator_name.to_string()))?;
        let delegations =
            delegator.signed.delegations.as_ref().ok_or_else(|| {
                Error::Malformed(format!("role {delegator_name} delegates nothing"))
            })?;
        let role = delegations
            .roles
            .iter()
            .find(|r| r.name == role_name)
            .ok_or_else(|| Error::UnknownRole(role_name.to_string()))?;

        // Only expose the keys this delegated role is allowed to use.
        let mut keys = BTreeMap::new();
        for kid in &role.keyids {
            if let Some(key) = delegations.keys.get(kid) {
                keys.insert(kid.clone(), key.clone());
            }
        }
        Ok((keys, role.role_keys()))
    }
}

/// Verify `metadata` against a named role defined in `root`.
fn verify_with_root<T: Role>(metadata: &Metadata<T>, root: &Root, role_name: &str) -> Result<()> {
    let role_keys = root
        .role(role_name)
        .ok_or_else(|| Error::UnknownRole(role_name.to_string()))?;
    metadata.verify_threshold(&root.keys, role_keys, role_name)
}

/// Verify a root is signed to threshold by its own `root` role.
fn verify_root_self_signed(root: &Metadata<Root>) -> Result<()> {
    let role_keys: &RoleKeys = root
        .signed
        .role("root")
        .ok_or_else(|| Error::UnknownRole("root".to_string()))?;
    let keys: &BTreeMap<String, Key> = &root.signed.keys;
    root.verify_threshold(keys, role_keys, "root")
}

fn ensure_not_expired<T: Role>(role: &T, name: &str, now: jiff::Timestamp) -> Result<()> {
    if role.is_expired(now)? {
        return Err(Error::Expired {
            role: name.to_string(),
            expires: role.expires().to_string(),
        });
    }
    Ok(())
}

/// Verify that `bytes` matches the length and hashes pinned in `meta`.
///
/// The length, if pinned, must match exactly. Every hash whose algorithm we
/// support (`sha256`, `sha512`) must match; at least one supported hash must be
/// present and verified so that integrity is actually enforced.
fn check_integrity(bytes: &[u8], meta: &MetaFile, what: &str) -> Result<()> {
    if let Some(expected_len) = meta.length {
        if bytes.len() as u64 != expected_len {
            return Err(Error::IntegrityMismatch(format!(
                "{what}: length {} != pinned {}",
                bytes.len(),
                expected_len
            )));
        }
    }

    let Some(hashes) = &meta.hashes else {
        // Nothing pinned to check against (length, if any, already verified).
        return Ok(());
    };

    let mut verified_any = false;
    for (algo, expected_hex) in hashes {
        let actual = match algo.as_str() {
            "sha256" => hex::encode(Sha256::digest(bytes)),
            "sha512" => hex::encode(Sha512::digest(bytes)),
            _ => continue, // unsupported algorithm; skip
        };
        if !actual.eq_ignore_ascii_case(expected_hex) {
            return Err(Error::IntegrityMismatch(format!("{what}: {algo} mismatch")));
        }
        verified_any = true;
    }

    if !verified_any {
        return Err(Error::IntegrityMismatch(format!(
            "{what}: no supported hash algorithm to verify ({:?})",
            hashes.keys().collect::<Vec<_>>()
        )));
    }
    Ok(())
}
