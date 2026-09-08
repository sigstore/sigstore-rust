# sigstore-types

Core types and data structures for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate provides the fundamental data types used throughout the sigstore-rust ecosystem. It defines serialization formats for bundles, transparency log entries, checkpoints, DSSE envelopes, and other Sigstore primitives.

This is the base crate with no dependencies on other sigstore crates. All other crates in the workspace depend on `sigstore-types`.

## Features

- **Artifact type**: `Artifact` enum for representing artifacts as bytes or pre-computed digests
- **Bundle types**: `Bundle`, `TransparencyLogEntry`, `VerificationMaterial`, `InclusionProof`
- **Checkpoint parsing**: `Checkpoint`, `CheckpointSignature` for signed tree heads
- **DSSE support**: `DsseEnvelope`, `DsseSignature` for Dead Simple Signing Envelope format
- **in-toto types**: `Statement`, `Subject` for attestation predicates
- **Hash types**: `Sha256Hash`, `HashAlgorithm`, `MessageImprint`
- **Encoding helpers**: Base64, hex, DER/PEM encoding newtypes with serde support

## Usage

```rust
use sigstore_types::{Artifact, Bundle, Checkpoint, Sha256Hash};

// Parse a Sigstore bundle
let bundle: Bundle = serde_json::from_str(bundle_json)?;

// Parse a checkpoint (signed tree head)
let checkpoint = Checkpoint::from_text(checkpoint_text)?;

// Create an artifact from bytes
let artifact = Artifact::Blob(b"hello world");

// Create an artifact from a pre-computed SHA-256 digest
// (useful for large files where you don't want to load the entire file into memory)
let digest = Sha256Hash::from_hex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")?;
let artifact = Artifact::Digest(digest);
```

## Related Crates

This crate is typically used indirectly through the higher-level APIs:

- [`sigstore-verify`](../sigstore-verify) - Signature verification
- [`sigstore-sign`](../sigstore-sign) - Signature creation

## License

Apache-2.0
