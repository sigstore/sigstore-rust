//! Transparency log verification
//!
//! This module handles verification of transparency log entries including
//! checkpoint verification and SET (Signed Entry Timestamp) verification.

use crate::error::{Error, Result};
use serde::Serialize;
use sigstore_crypto::Checkpoint;
use sigstore_crypto::{Keyring, VerificationKey};
use sigstore_types::bundle::InclusionProof;
use sigstore_types::{Bundle, KindVersion, Sha256Hash, SignatureBytes, TransparencyLogEntry};

/// Where the log keys for SET and checkpoint verification come from.
#[derive(Clone, Copy)]
pub(crate) enum LogKeys<'a> {
    /// Look keys up by log ID (SETs) or key hint (checkpoints), honoring
    /// their validity windows.
    Keyring(&'a Keyring),
    /// Use this key, whatever the entry's log ID or the checkpoint's hints.
    Single(&'a VerificationKey),
}

/// Verify transparency log entries (checkpoints, Merkle inclusion proofs and SETs)
///
/// For every tlog entry this cryptographically verifies (via
/// [`verify_entry_inclusion`]):
/// - the Merkle inclusion proof of the entry's canonicalized body against
///   the proof's root hash (if an inclusion proof is present),
/// - the checkpoint signature with the Rekor keys from the trusted root,
///   and that the checkpoint's root hash matches the proof's root hash,
/// - the inclusion promise (SET), if present.
///
/// It also validates the entry's integrated time against the certificate
/// validity window and the current time.
///
/// # Arguments
/// * `bundle` - The bundle containing transparency log entries
/// * `rekor_keys` - Trusted root for cryptographic verification
/// * `not_before` - Certificate validity start time (Unix timestamp)
/// * `not_after` - Certificate validity end time (Unix timestamp)
pub fn verify_tlog_entries(
    bundle: &Bundle,
    rekor_keys: &Keyring,
    not_before: jiff::Timestamp,
    not_after: jiff::Timestamp,
) -> Result<Option<jiff::Timestamp>> {
    let mut integrated_time_result: Option<jiff::Timestamp> = None;

    for entry in &bundle.verification_material.tlog_entries {
        // Verify Merkle inclusion proof, checkpoint signature and SET
        verify_entry_inclusion(entry, rekor_keys)?;

        // Only a Rekor v1 SET authenticates integratedTime. An inclusion proof
        // authenticates the body, not this separate timestamp field.
        let is_rekor_v2 = entry.kind_version == KindVersion::HashedRekordV002;
        if !is_rekor_v2 && entry.inclusion_promise.is_some() {
            if let Some(time) = entry.integrated_time {
                validate_integrated_time(time, jiff::Timestamp::now(), not_before, not_after)?;
                integrated_time_result = Some(earliest(integrated_time_result, time));
            }
        }
    }

    Ok(integrated_time_result)
}

/// The earlier of an optional time and `time`: the earliest log integration
/// is the strongest proof of when the signature existed.
pub(crate) fn earliest(current: Option<jiff::Timestamp>, time: jiff::Timestamp) -> jiff::Timestamp {
    current.map_or(time, |current| current.min(time))
}

/// Validate an entry's integrated time: it must not be in the future and
/// must fall within the certificate validity window.
fn validate_integrated_time(
    time: jiff::Timestamp,
    now: jiff::Timestamp,
    not_before: jiff::Timestamp,
    not_after: jiff::Timestamp,
) -> Result<()> {
    validate_integrated_time_not_in_future(time, now)?;

    // Check that integrated time is within certificate validity period
    if time < not_before || time > not_after {
        return Err(Error::integrated_time_outside_certificate(
            time, not_before, not_after,
        ));
    }

    Ok(())
}

pub(crate) fn validate_integrated_time_not_in_future(
    time: jiff::Timestamp,
    now: jiff::Timestamp,
) -> Result<()> {
    if time > now {
        return Err(
            crate::error::TransparencyLogError::IntegratedTimeInFuture { time, now }.into(),
        );
    }
    Ok(())
}

/// Cryptographically verify the log-inclusion material of a single tlog entry.
///
/// This performs all per-entry transparency log crypto checks:
/// - If an inclusion proof is present:
///   - verifies the Merkle inclusion proof, i.e. that the leaf hash of the
///     entry's canonicalized body hashes up to the authenticated root, and
///   - verifies the checkpoint signature against a Rekor key from the trusted
///     root (see [`verify_checkpoint`]). Rekor v1 additionally requires its
///     duplicated proof root to match the checkpoint root.
/// - If an inclusion promise (SET) is present, verifies it against the
///   Rekor key for the entry's log ID (see [`verify_set`]).
///
/// Time-related checks (integrated time vs. certificate validity) are not
/// performed here; see [`verify_tlog_entries`].
pub fn verify_entry_inclusion(entry: &TransparencyLogEntry, rekor_keys: &Keyring) -> Result<()> {
    verify_entry_inclusion_with(entry, LogKeys::Keyring(rekor_keys))
}

pub(crate) fn verify_entry_inclusion_with(
    entry: &TransparencyLogEntry,
    keys: LogKeys<'_>,
) -> Result<()> {
    if let Some(ref inclusion_proof) = entry.inclusion_proof {
        verify_merkle_inclusion(entry, inclusion_proof)?;
        verify_checkpoint_with(
            inclusion_proof.checkpoint.envelope(),
            inclusion_proof,
            is_rekor_v2(entry),
            keys,
        )?;
    }

    if entry.inclusion_promise.is_some() {
        verify_set_with(entry, keys)?;
    }

    Ok(())
}

/// Verify the Merkle inclusion proof of a tlog entry.
///
/// Computes the leaf hash of the entry's canonicalized body and verifies
/// that, combined with the proof hashes, it reproduces the expected root
/// hash. Rekor v2 takes the index, tree size, and root from the top-level entry
/// and signed checkpoint rather than unauthenticated duplicate proof fields.
/// The checkpoint signature check authenticates the selected root.
pub(crate) fn verify_merkle_inclusion(
    entry: &TransparencyLogEntry,
    proof: &InclusionProof,
) -> Result<()> {
    let (leaf_index, tree_size, root_hash) = if is_rekor_v2(entry) {
        let checkpoint = proof
            .checkpoint
            .checkpoint()
            .ok_or_else(|| Error::from(crate::error::TransparencyLogError::MissingCheckpoint))?;
        let leaf_index = entry.log_index.get();
        (leaf_index, checkpoint.tree_size(), *checkpoint.root_hash())
    } else {
        let leaf_index = proof.log_index.get();
        let tree_size = proof.tree_size;
        (leaf_index, tree_size, proof.root_hash)
    };

    let leaf_hash = sigstore_merkle::hash_leaf(entry.canonicalized_body.as_bytes());

    sigstore_merkle::verify_inclusion_proof(
        &leaf_hash,
        leaf_index,
        tree_size,
        &proof.hashes,
        &root_hash,
    )
    .map_err(|e| Error::inclusion_proof(format!("inclusion proof verification failed: {}", e)))
}

/// Verify a checkpoint's signature with the given log keys, and for Rekor v1
/// its consistency with the proof's duplicated root hash.
pub(crate) fn verify_checkpoint_with(
    checkpoint_envelope: &str,
    inclusion_proof: &InclusionProof,
    is_v2: bool,
    keys: LogKeys<'_>,
) -> Result<()> {
    // Parse the checkpoint (signed note)
    let checkpoint = Checkpoint::from_text(checkpoint_envelope)
        .map_err(|e| Error::checkpoint(format!("failed to parse checkpoint: {e}")))?;

    // Rekor v1 requires internal consistency with its duplicate proof root.
    // Rekor v2 explicitly treats that field as unauthenticated and ignores it.
    let checkpoint_root_hash = checkpoint.root_hash();
    let proof_root_hash = &inclusion_proof.root_hash;

    if !is_v2 && checkpoint_root_hash.as_bytes() != proof_root_hash.as_bytes() {
        return Err(crate::error::TransparencyLogError::CheckpointRootMismatch {
            checkpoint_root: *checkpoint_root_hash,
            proof_root: *proof_root_hash,
        }
        .into());
    }

    // A checkpoint can contain log and witness signatures. TrustedRoot keeps
    // validity metadata alongside each parsed verification key. Four-byte
    // checkpoint hints may collide, so try every matching key and do not let
    // an invalid matching signature suppress a later valid log signature.

    let message = checkpoint.signed_data();
    let now = jiff::Timestamp::now();
    let mut found_matching_key = false;
    for sig in checkpoint.signatures() {
        let candidates: Box<dyn Iterator<Item = &VerificationKey>> = match keys {
            LogKeys::Keyring(keyring) => Box::new(keyring.keys_by_hint(&sig.key_id, now)),
            // A single caller-chosen key: hints only narrow down lookups, so
            // try it against every signature on the note.
            LogKeys::Single(key) => Box::new(std::iter::once(key)),
        };
        for key in candidates {
            found_matching_key = true;
            if key.verify(message, &sig.signature).is_ok() {
                return Ok(());
            }
        }
    }

    if found_matching_key {
        Err(Error::checkpoint(
            "no valid Rekor signature found on checkpoint".to_string(),
        ))
    } else {
        Err(crate::error::TransparencyLogError::NoCheckpointKey.into())
    }
}

fn is_rekor_v2(entry: &TransparencyLogEntry) -> bool {
    entry.kind_version == KindVersion::HashedRekordV002
}

#[derive(Serialize)]
struct RekorPayload {
    body: String,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logIndex")]
    log_index: i64,
    #[serde(rename = "logID")]
    log_id: String,
}

/// Verify SET (Signed Entry Timestamp)
pub fn verify_set(entry: &TransparencyLogEntry, rekor_keys: &Keyring) -> Result<()> {
    verify_set_with(entry, LogKeys::Keyring(rekor_keys))
}

pub(crate) fn verify_set_with(entry: &TransparencyLogEntry, keys: LogKeys<'_>) -> Result<()> {
    let promise = entry
        .inclusion_promise
        .as_ref()
        .ok_or(crate::error::TransparencyLogError::MissingInclusionPromise)?;

    // Find the key for the log ID. When the entry carries an integrated
    // time, require the log key's validity window to cover it: an entry must
    // have been integrated while the log key was valid.
    let decoded_key_id = entry.log_id.key_id.as_bytes();
    let log_key = match keys {
        LogKeys::Single(key) => key,
        LogKeys::Keyring(keyring) => {
            let key_id = Sha256Hash::try_from(decoded_key_id)
                .map_err(|e| Error::malformed_entry(format!("invalid Rekor log ID: {e}")))?;
            if let Some(integrated_ts) = entry.integrated_time {
                keyring.key_at(&key_id, integrated_ts).ok_or_else(|| {
                    crate::error::TransparencyLogError::LogKeyNotValidAt {
                        log_id: entry.log_id.key_id.to_string(),
                        time: integrated_ts,
                    }
                })?
            } else {
                keyring
                    .key_started_by(&key_id, jiff::Timestamp::now())
                    .ok_or_else(|| Error::unknown_log(entry.log_id.key_id.to_string()))?
            }
        }
    };

    // Construct the payload (base64-encoded body)
    let body = entry.canonicalized_body.to_base64();
    let log_index = entry.log_index.as_i64();

    // Log ID for payload must be hex encoded
    let log_id_hex = hex::encode(decoded_key_id);

    let payload = RekorPayload {
        body,
        // The SET payload is wire-format Rekor V1 JSON, where "absent" is
        // the proto3 default of 0.
        integrated_time: entry.integrated_time.map_or(0, |ts| ts.as_second()),
        log_index,
        log_id: log_id_hex,
    };

    let canonical_json = serde_json_canonicalizer::to_vec(&payload)
        .map_err(|e| Error::inclusion_promise(format!("Canonicalization failed: {}", e)))?;

    // Get signature bytes from signed timestamp
    let signature = SignatureBytes::new(promise.signed_entry_timestamp.as_bytes().to_vec());

    log_key
        .verify(&canonical_json, &signature)
        .map_err(|e| Error::inclusion_promise(format!("SET verification failed: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(seconds: i64) -> jiff::Timestamp {
        jiff::Timestamp::from_second(seconds).unwrap()
    }

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn test_integrated_time_in_future_rejected() {
        // Even one second in the future must be rejected.
        let err = validate_integrated_time(ts(NOW + 1), ts(NOW), ts(NOW - 600), ts(NOW + 600))
            .unwrap_err();
        assert!(matches!(
            err,
            Error::TransparencyLog(crate::error::TransparencyLogError::IntegratedTimeInFuture {
                time,
                now
            }) if time == ts(NOW + 1) && now == ts(NOW)
        ));
    }

    #[test]
    fn test_integrated_time_outside_certificate_is_typed() {
        let err = validate_integrated_time(ts(NOW - 601), ts(NOW), ts(NOW - 600), ts(NOW + 600))
            .unwrap_err();
        assert!(matches!(
            err,
            Error::TransparencyLog(
                crate::error::TransparencyLogError::IntegratedTimeOutsideCertificate {
                    time,
                    not_before,
                    not_after,
                }
            ) if time == ts(NOW - 601) && not_before == ts(NOW - 600) && not_after == ts(NOW + 600)
        ));
    }

    #[test]
    fn test_integrated_time_at_now_accepted() {
        assert!(validate_integrated_time(ts(NOW), ts(NOW), ts(NOW - 600), ts(NOW + 600)).is_ok());
    }
}
