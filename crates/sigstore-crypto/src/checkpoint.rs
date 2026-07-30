//! Checkpoint verification extension trait.
//!
//! This module provides cryptographic verification capabilities for checkpoints
//! through an extension trait on `sigstore_types::Checkpoint`.

use crate::{Error, Result, VerificationKey};
use sigstore_types::{DerPublicKey, KeyHint};

// Re-export checkpoint types from sigstore-types
pub use sigstore_types::{Checkpoint, CheckpointSignature};

/// Compute the key hint (4-byte key ID) from a public key.
///
/// The key hint is the first 4 bytes of SHA-256(public key).
pub fn compute_key_hint(public_key: &DerPublicKey) -> KeyHint {
    let hash = crate::hash::sha256(public_key.as_bytes());
    let bytes = hash.as_bytes();
    KeyHint::new([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Extension trait for checkpoint signature verification.
///
/// This trait adds cryptographic verification capabilities to `Checkpoint`.
pub trait CheckpointVerifyExt {
    /// Verify the checkpoint signature using the provided public key.
    ///
    /// This verifies that the signature over the checkpoint text is valid.
    /// The public key should match the key hint in the signature.
    ///
    /// The key type is automatically detected from the SPKI structure.
    ///
    /// Returns Ok(()) if verification succeeds, or an error if it fails.
    fn verify_signature(&self, public_key: &DerPublicKey) -> Result<()>;
}

impl CheckpointVerifyExt for Checkpoint {
    fn verify_signature(&self, public_key: &DerPublicKey) -> Result<()> {
        // Compute key hint from public key
        let key_hint = compute_key_hint(public_key);

        // Find signature with matching key hint
        let signature = self
            .find_signature_by_key_hint(&key_hint)
            .ok_or_else(|| Error::Checkpoint("No signature found matching key hint".to_string()))?;

        // The signed data is the checkpoint text (without the signatures part)
        let signed_data = self.signed_data();

        VerificationKey::from_spki_auto(public_key)?
            .verify(signed_data, &signature.signature)
            .map_err(|e| Error::Checkpoint(format!("Signature verification failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_checkpoint() {
        let text = "rekor.sigstore.dev - 2605736670972794746\n23083062\ndauhleYK4YyAdxwwDtR0l0KnSOWZdG2bwqHftlanvcI=\nTimestamp: 1689177396617352539\n\n— rekor.sigstore.dev xNI9ajBFAiBxaGyEtxkzFLkaCSEJqFuSS3dJjEZCNiyByVs1CNVQ8gIhAOoNnXtmMtTctV2oRnSRUZAo4EWUYPK/vBsqOzAU6TMs";

        let checkpoint = Checkpoint::from_text(text).unwrap();
        assert_eq!(
            checkpoint.origin,
            "rekor.sigstore.dev - 2605736670972794746"
        );
        assert_eq!(checkpoint.tree_size, 23083062);
        assert_eq!(checkpoint.other_content.len(), 1);
        assert_eq!(
            checkpoint.other_content[0],
            "Timestamp: 1689177396617352539"
        );
    }

    #[test]
    fn test_parse_signature() {
        let text = "rekor.sigstore.dev - 2605736670972794746\n23083062\ndauhleYK4YyAdxwwDtR0l0KnSOWZdG2bwqHftlanvcI=\nTimestamp: 1689177396617352539\n\n— rekor.sigstore.dev xNI9ajBFAiBxaGyEtxkzFLkaCSEJqFuSS3dJjEZCNiyByVs1CNVQ8gIhAOoNnXtmMtTctV2oRnSRUZAo4EWUYPK/vBsqOzAU6TMs";

        let checkpoint = Checkpoint::from_text(text).unwrap();
        assert_eq!(checkpoint.signatures.len(), 1);
        assert_eq!(checkpoint.signatures[0].name, "rekor.sigstore.dev");
        // Key hint is first 4 bytes of base64-decoded signature
        assert_eq!(checkpoint.signatures[0].key_id.as_bytes().len(), 4);
    }
}
