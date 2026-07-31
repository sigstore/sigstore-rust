//! Checkpoint types and public key algorithm detection.

use sigstore_types::DerPublicKey;

// Re-export checkpoint types from sigstore-types
pub use sigstore_types::{Checkpoint, CheckpointSignature};

// OID constants for key type identification
use const_oid::db::rfc5912::ID_EC_PUBLIC_KEY;
use const_oid::ObjectIdentifier;

/// id-Ed25519: 1.3.101.112
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Key type detected from SPKI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519 key
    Ed25519,
    /// ECDSA P-256 key
    EcdsaP256,
    /// Unknown/unsupported key type
    Unknown,
}

/// Detect the key type from SPKI-encoded public key bytes.
///
/// This parses the SubjectPublicKeyInfo structure to determine the algorithm.
pub fn detect_key_type(public_key: &DerPublicKey) -> KeyType {
    use spki::SubjectPublicKeyInfoRef;

    match SubjectPublicKeyInfoRef::try_from(public_key.as_bytes()) {
        Ok(spki) => {
            if spki.algorithm.oid == ID_ED25519 {
                KeyType::Ed25519
            } else if spki.algorithm.oid == ID_EC_PUBLIC_KEY {
                KeyType::EcdsaP256
            } else {
                tracing::warn!("Unknown key algorithm OID: {}", spki.algorithm.oid);
                KeyType::Unknown
            }
        }
        Err(_) => {
            // If we can't parse as SPKI, might be raw key bytes
            // Check if it looks like a raw Ed25519 key (32 bytes)
            if public_key.as_bytes().len() == 32 {
                KeyType::Ed25519
            } else {
                KeyType::Unknown
            }
        }
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
