//! Merkle tree hashing utilities
//!
//! Implements RFC 6962 compliant Merkle tree hashing with:
//! - Domain separation via prefixes (0x00 for leaf, 0x01 for node)
//! - SHA-256 hash function

use sigstore_crypto::Sha256Hasher;
use sigstore_types::Sha256Hash;

/// Prefix for leaf nodes in RFC 6962 Merkle tree
pub const LEAF_HASH_PREFIX: u8 = 0x00;

/// Prefix for internal nodes in RFC 6962 Merkle tree
pub const NODE_HASH_PREFIX: u8 = 0x01;

/// Hash a leaf node
///
/// Returns: SHA256(0x00 || leaf_data)
pub fn hash_leaf(data: &[u8]) -> Sha256Hash {
    let mut hasher = Sha256Hasher::new();
    hasher.update(&[LEAF_HASH_PREFIX]);
    hasher.update(data);
    hasher.finalize()
}

/// Hash two child nodes to create a parent node
///
/// Returns: SHA256(0x01 || left || right)
pub fn hash_children(left: &Sha256Hash, right: &Sha256Hash) -> Sha256Hash {
    let mut hasher = Sha256Hasher::new();
    hasher.update(&[NODE_HASH_PREFIX]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_leaf() {
        let data = b"test data";
        let hash = hash_leaf(data);

        // Verify it's 32 bytes
        assert_eq!(hash.as_bytes().len(), 32);

        // Verify it's different from raw SHA256 (leaf hash has a prefix)
        let raw_hash = sigstore_crypto::sha256(data);
        assert_ne!(hash, raw_hash);
    }

    #[test]
    fn test_hash_children() {
        let left = Sha256Hash::from_bytes([0u8; 32]);
        let right = Sha256Hash::from_bytes([1u8; 32]);
        let hash = hash_children(&left, &right);

        assert_eq!(hash.as_bytes().len(), 32);

        // Verify order matters
        let hash_reversed = hash_children(&right, &left);
        assert_ne!(hash, hash_reversed);
    }
}
