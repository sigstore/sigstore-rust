//! TUF metadata model: the signed envelope and the four top-level roles.
//!
//! Every TUF metadata file is a JSON object of the form
//!
//! ```json
//! { "signed": { ... }, "signatures": [ { "keyid": "...", "sig": "..." } ] }
//! ```
//!
//! [`Metadata<T>`] captures that envelope generically. Crucially, it preserves
//! the *canonical* bytes of the `signed` object at parse time, because that is
//! exactly what the signatures cover — re-serializing the typed `signed` value
//! later could change byte-for-byte content (key order, escaping) and break
//! verification. See [`crate::canonical_json`] for why canonicalization is
//! securesystemslib-style and not RFC 8785.

mod role;
mod snapshot;
mod targets;

pub use role::{DelegatedRole, Delegations, RoleKeys, Root};
pub use snapshot::{MetaFile, Snapshot, Timestamp};
pub use targets::{TargetFile, Targets};

use std::collections::BTreeSet;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sigstore_types::SignatureBytes;

use crate::canonical_json;
use crate::error::{Error, Result};
use crate::key::Key;

/// A single signature over a metadata file's `signed` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// The declared ID of the key that produced this signature.
    pub keyid: String,
    /// The hex-encoded signature. For ecdsa this is an ASN.1/DER signature; an
    /// empty string denotes a placeholder (an authorized signer that has not yet
    /// signed) and is ignored.
    pub sig: String,
}

/// A role payload: knows its TUF `_type` string, version, and expiry.
///
/// Implemented by [`Root`], [`Timestamp`], [`Snapshot`], and [`Targets`] so the
/// envelope can run generic version/expiry checks.
pub trait Role: DeserializeOwned {
    /// The expected `_type` discriminator for this role.
    const TYPE: &'static str;

    /// The metadata version number.
    fn version(&self) -> u64;

    /// The raw `expires` timestamp string (RFC 3339).
    fn expires(&self) -> &str;

    /// Parse [`Role::expires`] into a [`jiff::Timestamp`].
    fn expires_at(&self) -> Result<jiff::Timestamp> {
        self.expires()
            .parse::<jiff::Timestamp>()
            .map_err(|source| Error::InvalidTimestamp {
                value: self.expires().to_string(),
                source,
            })
    }

    /// Whether this metadata is expired relative to `now`.
    fn is_expired(&self, now: jiff::Timestamp) -> Result<bool> {
        Ok(self.expires_at()? < now)
    }
}

/// A parsed, signed TUF metadata file.
#[derive(Debug, Clone)]
pub struct Metadata<T> {
    /// The signatures over the canonical `signed` bytes.
    pub signatures: Vec<Signature>,
    /// The typed, deserialized payload.
    pub signed: T,
    /// The canonical JSON bytes of the `signed` object — exactly what the
    /// signatures cover.
    canonical_signed: Vec<u8>,
}

impl<T: Role> Metadata<T> {
    /// Parse a signed metadata file from raw JSON bytes.
    ///
    /// Captures the canonical `signed` bytes for later signature verification
    /// and validates the `_type` discriminator.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Value = serde_json::from_slice(bytes)?;
        let obj = value
            .as_object()
            .ok_or_else(|| Error::Malformed("top level is not a JSON object".to_string()))?;

        let signed_value = obj
            .get("signed")
            .ok_or_else(|| Error::Malformed("missing `signed`".to_string()))?;
        let signatures_value = obj
            .get("signatures")
            .ok_or_else(|| Error::Malformed("missing `signatures`".to_string()))?;

        // Validate the role discriminator before doing anything else.
        if let Some(t) = signed_value.get("_type").and_then(Value::as_str) {
            if t != T::TYPE {
                return Err(Error::Malformed(format!(
                    "expected _type {:?}, found {:?}",
                    T::TYPE,
                    t
                )));
            }
        }

        // Reject metadata written against an incompatible (future) major spec
        // version: a 2.x file could carry semantics this client would silently
        // misinterpret. Matches python-tuf, which compares major versions only.
        // (A missing or non-string `spec_version` fails typed deserialization
        // below, since every role requires the field.)
        if let Some(sv) = signed_value.get("spec_version").and_then(Value::as_str) {
            if sv.split('.').next() != Some("1") {
                return Err(Error::Malformed(format!(
                    "unsupported TUF spec_version {sv:?} (this client implements 1.x)"
                )));
            }
        }

        let canonical_signed = canonical_json::to_canonical_bytes(signed_value)?;
        let signatures: Vec<Signature> = serde_json::from_value(signatures_value.clone())?;
        let signed: T = serde_json::from_value(signed_value.clone())?;

        Ok(Self {
            signatures,
            signed,
            canonical_signed,
        })
    }

    /// The canonical bytes that the signatures cover.
    pub fn signed_canonical(&self) -> &[u8] {
        &self.canonical_signed
    }

    /// Verify that this metadata carries at least `threshold` valid signatures
    /// from distinct keys drawn from `role_keys`, where the key material is
    /// looked up in `keys` by declared key ID.
    ///
    /// `role_name` is only used for error messages.
    pub fn verify_threshold(
        &self,
        keys: &std::collections::BTreeMap<String, Key>,
        role_keys: &RoleKeys,
        role_name: &str,
    ) -> Result<()> {
        // A threshold below 1 would make the check below pass with zero valid
        // signatures. No legitimate metadata declares one (python-tuf rejects
        // it at parse time); fail closed rather than verify vacuously.
        if role_keys.threshold == 0 {
            return Err(Error::Malformed(format!(
                "role {role_name} declares signature threshold 0; at least 1 is required"
            )));
        }
        let authorized: BTreeSet<&String> = role_keys.keyids.iter().collect();
        let mut good: BTreeSet<&str> = BTreeSet::new();
        let mut seen: BTreeSet<&str> = BTreeSet::new();

        for sig in &self.signatures {
            // The signature must be attributed to a key authorized for the role.
            if !authorized.contains(&sig.keyid) {
                continue;
            }
            // A placeholder (empty) signature is not a real signature; tuf-on-ci
            // roots carry these for authorized-but-not-yet-signed keys.
            if sig.sig.is_empty() {
                continue;
            }
            // The same key must not sign a role twice (spec-invalid; python-tuf
            // rejects it outright rather than silently de-duplicating).
            if !seen.insert(sig.keyid.as_str()) {
                return Err(Error::DuplicateSignature {
                    role: role_name.to_string(),
                    key_id: sig.keyid.clone(),
                });
            }
            let Some(key) = keys.get(&sig.keyid) else {
                continue;
            };

            let raw = match hex::decode(&sig.sig) {
                Ok(raw) => raw,
                Err(source) => {
                    tracing::debug!(key_id = %sig.keyid, %source, "skipping unparseable signature");
                    continue;
                }
            };

            let vkey = match key.verification_key() {
                Ok(vkey) => vkey,
                Err(e) => {
                    tracing::debug!(key_id = %sig.keyid, error = %e, "skipping unusable key");
                    continue;
                }
            };

            if vkey
                .verify(&self.canonical_signed, &SignatureBytes::new(raw))
                .is_ok()
            {
                good.insert(sig.keyid.as_str());
            }
        }

        if good.len() >= role_keys.threshold {
            Ok(())
        } else {
            Err(Error::ThresholdNotMet {
                role: role_name.to_string(),
                found: good.len(),
                threshold: role_keys.threshold,
            })
        }
    }
}
