# sigstore-crypto

Cryptographic primitives for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate provides key generation, signing, hashing, and verification functionality for the Sigstore ecosystem. By default it uses `aws-lc-rs` (`aws_lc_provider()`), and also exposes a pluggable [`CryptoProvider`](src/provider.rs) trait so downstream consumers can supply their own cryptographic backend without linking `aws-lc-sys`.

## Cargo Features

- **`aws-lc-rs`** *(default)*: Enables the built-in `aws-lc-rs` [`CryptoProvider`](src/provider.rs).

### Custom `CryptoProvider`

To use a custom cryptographic backend (such as BoringSSL, OpenSSL, RustCrypto, or an FFI function table), disable default features:

```toml
[dependencies]
sigstore-crypto = { version = "0.14", default-features = false }
```

Implement [`CryptoProvider`](src/provider.rs) and register it at startup via `sigstore_crypto::install_default_provider(&MY_PROVIDER)`. See [`tests/boring_provider.rs`](tests/boring_provider.rs) for a complete reference implementation using the `boring` (BoringSSL) crate.

## Features

- **Key generation & signing**: Ephemeral ECDSA P-256 key generation, PKCS#8 loading, and signing
- **Verification**: ECDSA (P-256/P-384), Ed25519, RSA (PKCS#1 v1.5 and PSS, 2048–8192 bits), and ML-DSA (44/65/87), plus `rustls-webpki` verification algorithms (`WEBPKI_VERIFICATION_ALGS`)
- **Checkpoint verification**: Extension trait for verifying signed tree head signatures
- **Certificate parsing**: X.509 certificate information extraction
- **Keyring**: Key management for multi-key verification scenarios
- **Hash functions**: SHA-256, SHA-384, SHA-512 (one-shot and streaming/async readers)

## Supported Algorithms

| Algorithm | Key Generation | Signing | Verification |
|-----------|---------------|---------|--------------|
| ECDSA P-256 (SHA-256 / SHA-384) | Yes | Yes (SHA-256) | Yes |
| ECDSA P-384 (SHA-256 / SHA-384) | No | No | Yes |
| Ed25519 | No | No | Yes |
| RSA PKCS#1 v1.5 & PSS (SHA-256 / SHA-384 / SHA-512) | No | No | Yes |
| ML-DSA-44 / ML-DSA-65 / ML-DSA-87 | No | No | Yes |

## Usage

```rust
use sigstore_crypto::{KeyPair, SigningScheme, verify_signature};

// Generate a new ECDSA P-256 key pair
let keypair = KeyPair::generate_ecdsa_p256()?;

// Sign data
let signature = keypair.sign(b"message")?;
let public_key_der = keypair.public_key_der()?;

// Verify a signature
verify_signature(
    &public_key_der,
    b"message",
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
