//! Error types for sigstore-merkle

use sigstore_types::Sha256Hash;
use thiserror::Error;

/// Errors that can occur in Merkle tree operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An inclusion proof was given for an empty tree
    #[error("tree size cannot be zero")]
    EmptyTree,

    /// The leaf index does not fall inside the tree
    #[error("leaf index {leaf_index} is outside a tree of size {tree_size}")]
    LeafIndexOutOfRange {
        /// The claimed leaf index
        leaf_index: u64,
        /// The tree size
        tree_size: u64,
    },

    /// A consistency proof was given for a tree that shrank
    #[error("old tree size {old_size} exceeds new tree size {new_size}")]
    TreeSizeDecreased {
        /// The size of the older tree
        old_size: u64,
        /// The size of the newer tree
        new_size: u64,
    },

    /// The proof has the wrong number of hashes for the claimed tree shape
    #[error("expected {expected} proof hashes, got {actual}")]
    WrongProofLength {
        /// The number of hashes the tree shape requires
        expected: usize,
        /// The number of hashes supplied
        actual: usize,
    },

    /// The root computed from the proof does not match the expected root
    #[error(
        "root hash mismatch: expected {}, computed {}",
        expected.to_hex(),
        actual.to_hex()
    )]
    RootMismatch {
        /// The trusted root hash
        expected: Sha256Hash,
        /// The root hash computed from the proof
        actual: Sha256Hash,
    },
}

/// Result type for Merkle tree operations
pub type Result<T> = std::result::Result<T, Error>;
