//! Structural bundle validation
//!
//! This module performs *structural* validation of Sigstore bundles: it
//! checks that a bundle has the shape and required fields mandated by its
//! media-type version (v0.1, v0.2, v0.3).
//!
//! It deliberately performs **no cryptographic verification**. In
//! particular, the functions in this module do NOT:
//!
//! - verify the artifact or DSSE signature,
//! - verify Merkle inclusion proofs against the log root,
//! - verify checkpoint (signed tree head) signatures,
//! - verify inclusion promises (SETs),
//! - verify RFC 3161 timestamps,
//! - verify the certificate chain or certificate contents.
//!
//! Cryptographic verification of all of the above is the responsibility of
//! the verification path in the `sigstore-verify` crate (see
//! `sigstore_verify::verify` / `Verifier`), which has access to the trusted
//! root material required to do so.

use crate::error::{Error, Result};
use sigstore_types::{Bundle, MediaType};

/// Options controlling which materials must be *present* in the bundle.
///
/// These options only affect presence/shape requirements; they never enable
/// cryptographic checks (structural validation performs none).
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Require an inclusion proof to be present (not just an inclusion
    /// promise). Note that presence is all that is checked; the proof is
    /// not cryptographically verified here.
    pub require_inclusion_proof: bool,
    /// Require RFC 3161 timestamp verification data to be present. The
    /// timestamps themselves are not verified here.
    pub require_timestamp: bool,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            require_inclusion_proof: true,
            require_timestamp: false,
        }
    }
}

/// Structurally validate a Sigstore bundle using default [`ValidationOptions`].
///
/// This is a purely *structural* check: it confirms the bundle conforms to
/// the shape required by its media-type version. See
/// [`validate_bundle_with_options`] for the full list of what is and is not
/// checked.
///
/// # What this does NOT do
///
/// No cryptographic verification is performed: signatures, Merkle inclusion
/// proofs, checkpoint signatures, inclusion promises (SETs), timestamps and
/// certificates are **not** verified. A bundle passing this function may
/// still be forged or tampered with; use `sigstore-verify` to actually
/// verify it.
pub fn validate_bundle(bundle: &Bundle) -> Result<()> {
    validate_bundle_with_options(bundle, &ValidationOptions::default())
}

/// Structurally validate a Sigstore bundle with custom options.
///
/// # What is checked (structural only)
///
/// - The media type is a known bundle version (v0.1, v0.2, v0.3).
/// - Version-specific shape requirements:
///   - v0.1: an inclusion promise (SET) must be present.
///   - v0.2/v0.3: an inclusion proof must be present (if
///     [`ValidationOptions::require_inclusion_proof`] is set).
///   - v0.3: the verification material must be a single certificate or a
///     public key, not a certificate chain.
/// - Each inclusion proof that is present is well-formed: its checkpoint
///   envelope parses, its `log_index`/`tree_size` are in range, and its
///   `root_hash` is consistent with the root hash embedded in its
///   checkpoint. (Consistency between two fields of the same bundle is a
///   well-formedness check, not a trust decision.)
/// - At least one transparency log entry or RFC 3161 timestamp is present
///   (depending on options).
///
/// # What is NOT checked
///
/// No cryptographic verification of any kind is performed. In particular,
/// this function does **not**:
///
/// - verify the artifact or DSSE signature,
/// - verify Merkle inclusion proofs against the log root,
/// - verify checkpoint (signed tree head) signatures,
/// - verify inclusion promises (SETs),
/// - verify RFC 3161 timestamps,
/// - verify the certificate chain or its contents.
///
/// Those checks require trusted key material and are performed by the
/// verification path in the `sigstore-verify` crate.
pub fn validate_bundle_with_options(bundle: &Bundle, options: &ValidationOptions) -> Result<()> {
    // Check media type is valid
    let version = bundle
        .version()
        .map_err(|e| Error::Validation(format!("invalid media type: {}", e)))?;

    // Version-specific validation
    match version {
        MediaType::Bundle0_1 => validate_v0_1(bundle, options),
        MediaType::Bundle0_2 => validate_v0_2(bundle, options),
        MediaType::Bundle0_3 => validate_v0_3(bundle, options),
    }
}

/// Structurally validate a v0.1 bundle
fn validate_v0_1(bundle: &Bundle, options: &ValidationOptions) -> Result<()> {
    // v0.1 requires inclusion promise (SET)
    if !bundle.has_inclusion_promise() {
        return Err(Error::Validation(
            "v0.1 bundle must have inclusion promise".to_string(),
        ));
    }

    // Check well-formedness of inclusion proofs if present
    // (v0.1 may have both promise and proof)
    validate_inclusion_proof_structure(bundle)?;

    // Common validation
    validate_common(bundle, options)
}

/// Structurally validate a v0.2 bundle
fn validate_v0_2(bundle: &Bundle, options: &ValidationOptions) -> Result<()> {
    // v0.2 requires inclusion proof with checkpoint
    if options.require_inclusion_proof && !bundle.has_inclusion_proof() {
        return Err(Error::Validation(
            "v0.2 bundle must have inclusion proof".to_string(),
        ));
    }

    // Check well-formedness of inclusion proofs
    validate_inclusion_proof_structure(bundle)?;

    // Common validation
    validate_common(bundle, options)
}

/// Structurally validate a v0.3 bundle
fn validate_v0_3(bundle: &Bundle, options: &ValidationOptions) -> Result<()> {
    // v0.3 must have single certificate (not chain) or public key
    match &bundle.verification_material.content {
        sigstore_types::bundle::VerificationMaterialContent::Certificate(_) => {}
        sigstore_types::bundle::VerificationMaterialContent::X509CertificateChain { .. } => {
            return Err(Error::Validation(
                "v0.3 bundle must use single certificate, not chain".to_string(),
            ));
        }
        sigstore_types::bundle::VerificationMaterialContent::PublicKey { .. } => {}
    }

    // v0.3 requires inclusion proof
    if options.require_inclusion_proof && !bundle.has_inclusion_proof() {
        return Err(Error::Validation(
            "v0.3 bundle must have inclusion proof".to_string(),
        ));
    }

    // Check well-formedness of inclusion proofs
    validate_inclusion_proof_structure(bundle)?;

    // Common validation
    validate_common(bundle, options)
}

/// Common structural validation for all bundle versions
fn validate_common(bundle: &Bundle, options: &ValidationOptions) -> Result<()> {
    let has_tlog_entries = !bundle.verification_material.tlog_entries.is_empty();
    let has_timestamp = !bundle
        .verification_material
        .timestamp_verification_data
        .rfc3161_timestamps
        .is_empty();

    // Bundles verified without transparency-log requirements may establish
    // signing time from RFC3161 timestamp data alone.
    if !has_tlog_entries && (options.require_inclusion_proof || !has_timestamp) {
        return Err(Error::Validation(
            "bundle must have at least one tlog entry or timestamp verification data".to_string(),
        ));
    }

    // Check timestamp if required
    if options.require_timestamp && !has_timestamp {
        return Err(Error::Validation(
            "bundle must have timestamp verification data".to_string(),
        ));
    }

    Ok(())
}

/// Check that any inclusion proofs in the bundle are well-formed.
///
/// This is a structural check only:
///
/// - the checkpoint envelope must parse as a signed note,
/// - `log_index` and `tree_size` must be valid and in range
///   (`log_index < tree_size`),
/// - the proof's `root_hash` must equal the root hash embedded in its own
///   checkpoint (internal consistency between two fields of the bundle).
///
/// It does NOT verify the Merkle proof against the root hash, and it does
/// NOT verify the checkpoint signature. Those cryptographic checks are
/// performed by the verification path in `sigstore-verify`.
fn validate_inclusion_proof_structure(bundle: &Bundle) -> Result<()> {
    for entry in &bundle.verification_material.tlog_entries {
        if let Some(proof) = &entry.inclusion_proof {
            // The checkpoint must be a parseable signed note
            let checkpoint = proof
                .checkpoint
                .parse()
                .map_err(|e| Error::Validation(format!("failed to parse checkpoint: {}", e)))?;

            // Indices must be valid and in range
            let leaf_index: u64 = proof
                .log_index
                .as_u64()
                .ok_or_else(|| Error::Validation("invalid log_index in proof".to_string()))?;
            let tree_size: u64 = proof
                .tree_size
                .try_into()
                .map_err(|_| Error::Validation("invalid tree_size in proof".to_string()))?;
            if leaf_index >= tree_size {
                return Err(Error::Validation(format!(
                    "inclusion proof log_index {} out of range for tree_size {}",
                    leaf_index, tree_size
                )));
            }

            // The proof's root hash must be consistent with the root hash
            // recorded in its own checkpoint. This is internal consistency
            // of the bundle, not a trust decision: neither hash has been
            // authenticated at this point.
            if checkpoint.root_hash != proof.root_hash {
                return Err(Error::Validation(
                    "inclusion proof root hash does not match checkpoint root hash".to_string(),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_options_default() {
        let opts = ValidationOptions::default();
        assert!(opts.require_inclusion_proof);
        assert!(!opts.require_timestamp);
    }
}
