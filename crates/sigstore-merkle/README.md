# sigstore-merkle

RFC 6962 Merkle tree verification for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate implements Merkle tree operations as specified in RFC 6962 (Certificate Transparency). It provides inclusion proof verification for transparency logs like Rekor.

## Features

- **Inclusion proof verification**: Verify that an entry exists in a Merkle tree
- **Hash chaining**: RFC 6962 compliant hash computation for tree nodes
- **Proof path validation**: Verify proof paths against known root hashes

## Usage

```rust
use sigstore_merkle::verify_inclusion;
use sigstore_types::Sha256Hash;

// Verify an inclusion proof
verify_inclusion(
    leaf_index,
    tree_size,
    &proof_hashes,
    &root_hash,
    &leaf_hash,
)?;
```

## Background

Merkle trees in transparency logs allow clients to verify that:

1. A specific entry exists in the log (inclusion proof)
2. The log is append-only and consistent (consistency proof)

This crate focuses on inclusion proof verification, which is the primary operation needed for Sigstore bundle verification.

## Related Crates

Used by:

- [`sigstore-verify`](../sigstore-verify) - Verifies inclusion proofs in bundles
- [`sigstore-bundle`](../sigstore-bundle) - Bundle validation

## License

Apache-2.0
