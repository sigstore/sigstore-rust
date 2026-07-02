//! TUF key handling.
//!
//! # Declared key IDs are authoritative
//!
//! A TUF key ID is, per the specification, an *opaque* identifier chosen by the
//! metadata producer. There is no requirement that `keyid == hash(key)`. Both
//! `python-tuf` (sigstore-python) and `go-tuf` (sigstore-go) treat the declared
//! key ID as authoritative: they index keys by the ID written in the metadata
//! and never recompute-and-reject.
//!
//! `tough` does the opposite — it recomputes each key's ID over the *entire*
//! `Key` struct (including non-standard fields such as `x-tuf-on-ci-keyowner`)
//! and rejects metadata whose declared IDs don't match. That makes it
//! non-interoperable with any `tuf-on-ci` / `securesystemslib`-produced
//! repository, including GitHub's (`https://tuf-repo.github.com`). This crate
//! deliberately follows the `python-tuf`/`go-tuf` behavior so the same roots
//! load everywhere.
//!
//! [`Key::key_id`] is still provided for the signing/editor path, but loading
//! never depends on it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sigstore_crypto::{SigningScheme, VerificationKey};
use sigstore_types::DerPublicKey;

use crate::canonical_json;
use crate::error::{Error, Result};

/// The inner `keyval` object of a TUF key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVal {
    /// The public key material. Either a PEM `SubjectPublicKeyInfo` blob
    /// (ecdsa/rsa) or a hex-encoded raw public key (ed25519).
    pub public: String,
    /// Any additional, producer-specific fields (preserved verbatim).
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// A public key as declared in TUF metadata.
///
/// Unknown fields (e.g. `x-tuf-on-ci-keyowner`) are preserved in [`Key::extra`]
/// so that round-tripping and editor workflows do not silently drop data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    /// The key type, e.g. `ecdsa`, `ed25519`, `rsa`.
    pub keytype: String,
    /// The signing scheme, e.g. `ecdsa-sha2-nistp256`, `ed25519`,
    /// `rsassa-pss-sha256`.
    pub scheme: String,
    /// The key value.
    pub keyval: KeyVal,
    /// Producer-specific fields not part of the core TUF key object.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Key {
    /// Compute the canonical TUF key ID for this key.
    ///
    /// This hashes the canonical JSON of `{keytype, scheme, keyval}` — the
    /// fields that `securesystemslib` includes — and excludes producer-specific
    /// extras such as `x-tuf-on-ci-keyowner`. It matches the IDs declared by
    /// modern `tuf-on-ci` repositories.
    ///
    /// This is provided for signing/editor flows. **Loading and verification do
    /// not use it**: declared key IDs are authoritative (see the module docs).
    pub fn key_id(&self) -> Result<String> {
        // Build the canonical key object explicitly so extras are excluded and
        // the field set is exactly what securesystemslib hashes.
        let keyval = {
            let mut m = serde_json::Map::new();
            m.insert(
                "public".to_string(),
                Value::String(self.keyval.public.clone()),
            );
            Value::Object(m)
        };
        let mut obj = serde_json::Map::new();
        obj.insert("keytype".to_string(), Value::String(self.keytype.clone()));
        obj.insert("scheme".to_string(), Value::String(self.scheme.clone()));
        obj.insert("keyval".to_string(), keyval);
        let canonical = canonical_json::to_canonical_bytes(&Value::Object(obj))?;
        Ok(hex::encode(sigstore_crypto::sha256(&canonical).as_bytes()))
    }

    /// Resolve the [`SigningScheme`] implied by this key's `scheme`/`keytype`.
    pub fn signing_scheme(&self) -> Result<SigningScheme> {
        let scheme = match self.scheme.as_str() {
            "ecdsa-sha2-nistp256" => SigningScheme::EcdsaP256Sha256,
            "ecdsa-sha2-nistp384" => SigningScheme::EcdsaP384Sha384,
            "ed25519" => SigningScheme::Ed25519,
            "rsassa-pss-sha256" => SigningScheme::RsaPssSha256,
            "rsassa-pss-sha384" => SigningScheme::RsaPssSha384,
            "rsassa-pss-sha512" => SigningScheme::RsaPssSha512,
            "ml-dsa-44/1" => SigningScheme::MlDsa44,
            "ml-dsa-65/1" => SigningScheme::MlDsa65,
            "ml-dsa-87/1" => SigningScheme::MlDsa87,
            _ => {
                return Err(Error::UnsupportedScheme {
                    keytype: self.keytype.clone(),
                    scheme: self.scheme.clone(),
                })
            }
        };
        Ok(scheme)
    }

    /// Build a [`VerificationKey`] usable for checking signatures.
    ///
    /// Accepts both PEM `SubjectPublicKeyInfo` blobs (ecdsa/rsa, and ed25519 if
    /// PEM-encoded) and hex-encoded raw ed25519 public keys, which are wrapped
    /// into SPKI before parsing.
    pub fn verification_key(&self) -> Result<VerificationKey> {
        let scheme = self.signing_scheme()?;
        let public = self.keyval.public.trim();

        let der = if public.starts_with("-----BEGIN") {
            DerPublicKey::from_pem(public).map_err(|e| Error::UnusableKey {
                key_id: self.key_id().unwrap_or_default(),
                reason: format!("invalid PEM public key: {e}"),
            })?
        } else if matches!(scheme, SigningScheme::Ed25519) {
            // TUF ed25519 keys are a hex-encoded 32-byte raw public key. Wrap it
            // in a minimal SPKI so the shared parser can consume it.
            let raw = hex::decode(public).map_err(|e| Error::UnusableKey {
                key_id: self.key_id().unwrap_or_default(),
                reason: format!("ed25519 public key is not valid hex: {e}"),
            })?;
            DerPublicKey::new(ed25519_spki(&raw)?)
        } else {
            return Err(Error::UnusableKey {
                key_id: self.key_id().unwrap_or_default(),
                reason: "public key is neither PEM nor a hex ed25519 key".to_string(),
            });
        };

        VerificationKey::from_spki(&der, scheme).map_err(Error::from)
    }

    /// Verify a signature over `data`.
    ///
    /// For ML-DSA schemes, this automatically applies the TUF-specific `tuf\x01`
    /// domain separator and SHA-512 pre-hash before passing to the underlying
    /// verifier, as required by the TAP 21 specification.
    pub fn verify(&self, data: &[u8], signature: &sigstore_types::SignatureBytes) -> Result<()> {
        let vkey = self.verification_key()?;
        let scheme = vkey.scheme();

        if matches!(
            scheme,
            SigningScheme::MlDsa44 | SigningScheme::MlDsa65 | SigningScheme::MlDsa87
        ) {
            use sha2::{Digest, Sha512};
            let mut hasher = Sha512::new();
            hasher.update(data);
            let digest = hasher.finalize();

            let mut payload = Vec::with_capacity(4 + digest.len());
            payload.extend_from_slice(b"tuf\x01");
            payload.extend_from_slice(&digest);

            vkey.verify(&payload, signature).map_err(Error::from)
        } else {
            vkey.verify(data, signature).map_err(Error::from)
        }
    }
}

/// Wrap a 32-byte raw ed25519 public key in a DER `SubjectPublicKeyInfo`.
///
/// The SPKI prefix `30 2a 30 05 06 03 2b 65 70 03 21 00` encodes the
/// `id-Ed25519` algorithm identifier (OID 1.3.101.112) and the BIT STRING
/// header for the 256-bit key that follows.
fn ed25519_spki(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() != 32 {
        return Err(Error::UnusableKey {
            key_id: String::new(),
            reason: format!("ed25519 public key must be 32 bytes, got {}", raw.len()),
        });
    }
    const PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut der = Vec::with_capacity(PREFIX.len() + raw.len());
    der.extend_from_slice(&PREFIX);
    der.extend_from_slice(raw);
    Ok(der)
}
