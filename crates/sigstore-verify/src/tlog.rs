//! Low-level transparency log checks for a single log entry.
//!
//! [`Verifier`](crate::Verifier) runs these checks as part of bundle
//! verification. They are exposed for callers that verify transparency log
//! entries themselves, for example to control the order of checks or to use
//! log keys that are not in a trusted root.
//!
//! Each check comes in two forms:
//!
//! - with a [`Keyring`]: the key is selected by the entry's log ID (SETs) or
//!   by the checkpoint signature's key hint (checkpoints), and must be valid
//!   at the entry's integrated time, as during bundle verification;
//! - with a single [`VerificationKey`] (`*_with_key`): that key is used
//!   whatever the entry's log ID or the checkpoint's key hints say.
//!
//! None of these checks relate the entry to a bundle or an artifact, and none
//! check the integrated time against a certificate's validity. A verified
//! entry only proves that the log included *this entry*; the caller must still
//! check that the entry describes the signature at hand.

use crate::error::{Error, Result};
use crate::verify_impl::tlog::{
    verify_checkpoint_with, verify_entry_inclusion_with, verify_merkle_inclusion, verify_set_with,
    LogKeys,
};
use sigstore_crypto::{Keyring, VerificationKey};
use sigstore_types::{KindVersion, TransparencyLogEntry};

/// Verify the entry's Merkle inclusion proof.
///
/// Checks that the leaf hash of the entry's canonicalized body, combined
/// with the proof hashes, reproduces the proof's root hash (for Rekor v2,
/// the root hash in the signed checkpoint). Fails if the entry has no
/// inclusion proof.
///
/// This alone authenticates nothing: the root hash is only trustworthy once
/// [`verify_checkpoint`] (or [`verify_checkpoint_with_key`]) has verified the
/// checkpoint that carries it.
pub fn verify_inclusion_proof(entry: &TransparencyLogEntry) -> Result<()> {
    verify_merkle_inclusion(entry, inclusion_proof(entry)?)
}

/// Verify the signature on the entry's checkpoint with keys from `keys`.
///
/// For Rekor v1 the checkpoint's root hash must also equal the inclusion
/// proof's root hash. Fails if the entry has no inclusion proof. Does not
/// verify the Merkle proof itself; see [`verify_inclusion_proof`].
pub fn verify_checkpoint(entry: &TransparencyLogEntry, keys: &Keyring) -> Result<()> {
    checkpoint(entry, LogKeys::Keyring(keys))
}

/// Like [`verify_checkpoint`], with a single log key, tried against every
/// signature on the checkpoint regardless of its key hint.
pub fn verify_checkpoint_with_key(
    entry: &TransparencyLogEntry,
    key: &VerificationKey,
) -> Result<()> {
    checkpoint(entry, LogKeys::Single(key))
}

/// Verify the entry's inclusion promise (SET) with the key in `keys` for
/// the entry's log ID.
///
/// The SET signs the entry's body, integrated time, log index and log ID, so
/// a verified SET authenticates the integrated time. When the entry carries
/// an integrated time, the key must be valid at that time. Fails if the entry
/// has no inclusion promise.
pub fn verify_set(entry: &TransparencyLogEntry, keys: &Keyring) -> Result<()> {
    verify_set_with(entry, LogKeys::Keyring(keys))
}

/// Like [`verify_set`], with a single log key used whatever the entry's log
/// ID, and without a validity window.
pub fn verify_set_with_key(entry: &TransparencyLogEntry, key: &VerificationKey) -> Result<()> {
    verify_set_with(entry, LogKeys::Single(key))
}

/// Verify all log-inclusion evidence the entry carries: the inclusion proof
/// and its checkpoint, if present, and the inclusion promise (SET), if
/// present.
///
/// Fails if the entry carries neither an inclusion proof nor an inclusion
/// promise.
pub fn verify_entry_inclusion(entry: &TransparencyLogEntry, keys: &Keyring) -> Result<()> {
    require_evidence(entry)?;
    verify_entry_inclusion_with(entry, LogKeys::Keyring(keys))
}

/// Like [`verify_entry_inclusion`], with a single log key; see
/// [`verify_checkpoint_with_key`] and [`verify_set_with_key`].
pub fn verify_entry_inclusion_with_key(
    entry: &TransparencyLogEntry,
    key: &VerificationKey,
) -> Result<()> {
    require_evidence(entry)?;
    verify_entry_inclusion_with(entry, LogKeys::Single(key))
}

fn inclusion_proof(
    entry: &TransparencyLogEntry,
) -> Result<&sigstore_types::bundle::InclusionProof> {
    entry
        .inclusion_proof
        .as_ref()
        .ok_or_else(|| Error::inclusion_proof("log entry has no inclusion proof".to_string()))
}

fn checkpoint(entry: &TransparencyLogEntry, keys: LogKeys<'_>) -> Result<()> {
    let proof = inclusion_proof(entry)?;
    verify_checkpoint_with(
        proof.checkpoint.envelope(),
        proof,
        entry.kind_version == KindVersion::HashedRekordV002,
        keys,
    )
}

fn require_evidence(entry: &TransparencyLogEntry) -> Result<()> {
    if entry.inclusion_proof.is_none() && entry.inclusion_promise.is_none() {
        return Err(Error::inclusion_proof(
            "log entry has neither an inclusion proof nor an inclusion promise".to_string(),
        ));
    }
    Ok(())
}
