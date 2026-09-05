# sigstore-crypto

Cryptographic primitives for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate provides key generation, signing, and verification functionality using `aws-lc-rs` as the cryptographic backend. It supports the key types and signature algorithms used in the Sigstore ecosystem.

## Features

- **Key generation**: Ed25519, ECDSA P-256, ECDSA P-384
- **Signing and verification**: Multiple signature schemes with automatic algorithm detection
- **Checkpoint verification**: Extension trait for verifying signed tree head signatures
- **Certificate parsing**: X.509 certificate information extraction
- **Keyring**: Key management for multi-key verification scenarios
- **Hash functions**: SHA-256, SHA-384, SHA-512

## Supported Algorithms

| Algorithm | Key Generation | Signing | Verification |
|-----------|---------------|---------|--------------|
| Ed25519 | Yes | Yes | Yes |
| ECDSA P-256 (SHA-256) | Yes | Yes | Yes |
| ECDSA P-384 (SHA-384) | Yes | Yes | Yes |

## Usage

```rust
use sigstore_crypto::{KeyPair, SigningScheme, verify_signature};

// Generate a new key pair
let keypair = KeyPair::generate(SigningScheme::EcdsaP256Sha256)?;

// Sign data
let signature = keypair.sign(b"message")?;

// Verify a signature
verify_signature(
    &public_key_der,
    message,
    &signature,
    SigningScheme::EcdsaP256Sha256,
)?;
```

## Related Crates

This crate provides cryptographic operations for:

- [`sigstore-verify`](../sigstore-verify) - Signature verification
- [`sigstore-sign`](../sigstore-sign) - Signature creation

## License

Apache-2.0
