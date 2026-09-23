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
        let key_hint = compute_key_hint(public_key);
        let key = VerificationKey::from_spki(public_key)?;
        let signed_data = self.signed_data();

        // Key hints are only 4 bytes and can collide, so a mismatching signature
        // with the same hint must not hide a valid one.
        let mut last_error = None;
        for signature in self.signatures_by_key_hint(&key_hint) {
            match key.verify(signed_data, &signature.signature) {
                Ok(()) => return Ok(()),
                Err(e) => last_error = Some(e),
            }
        }
        Err(match last_error {
            Some(e) => Error::Checkpoint(format!("Signature verification failed: {}", e)),
            None => Error::Checkpoint("No signature found matching key hint".to_string()),
        })
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
            checkpoint.origin(),
            "rekor.sigstore.dev - 2605736670972794746"
        );
        assert_eq!(checkpoint.tree_size(), 23083062);
        assert_eq!(checkpoint.other_content().len(), 1);
        assert_eq!(
            checkpoint.other_content()[0],
            "Timestamp: 1689177396617352539"
        );
    }

    #[test]
    fn test_parse_signature() {
        let text = "rekor.sigstore.dev - 2605736670972794746\n23083062\ndauhleYK4YyAdxwwDtR0l0KnSOWZdG2bwqHftlanvcI=\nTimestamp: 1689177396617352539\n\n— rekor.sigstore.dev xNI9ajBFAiBxaGyEtxkzFLkaCSEJqFuSS3dJjEZCNiyByVs1CNVQ8gIhAOoNnXtmMtTctV2oRnSRUZAo4EWUYPK/vBsqOzAU6TMs";

        let checkpoint = Checkpoint::from_text(text).unwrap();
        assert_eq!(checkpoint.signatures().len(), 1);
        assert_eq!(checkpoint.signatures()[0].name, "rekor.sigstore.dev");
        // Key hint is first 4 bytes of base64-decoded signature
        assert_eq!(checkpoint.signatures()[0].key_id.as_bytes().len(), 4);
    }

    #[test]
    fn verify_signature_tries_every_signature_with_a_colliding_hint() {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;

        let key_pair = crate::KeyPair::generate_ecdsa_p256().unwrap();
        let public_key = key_pair.public_key_der().unwrap();
        let hint = compute_key_hint(&public_key);
        let body = "example.com/log\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
        let valid = key_pair.sign(body.as_bytes()).unwrap();

        let note_line = |name: &str, signature: &[u8]| {
            let mut bytes = hint.as_bytes().to_vec();
            bytes.extend_from_slice(signature);
            format!("\u{2014} {name} {}\n", engine.encode(bytes))
        };
        // An invalid signature with the same key hint comes first.
        let text = format!(
            "{body}\n{}{}",
            note_line("bogus", &[0u8; 64]),
            note_line("real", valid.as_bytes())
        );
        let checkpoint = Checkpoint::from_text(&text).unwrap();
        checkpoint.verify_signature(&public_key).unwrap();

        let only_bogus = format!("{body}\n{}", note_line("bogus", &[0u8; 64]));
        let checkpoint = Checkpoint::from_text(&only_bogus).unwrap();
        let error = checkpoint.verify_signature(&public_key).unwrap_err();
        assert!(error.to_string().contains("Signature verification failed"));
    }
}
