# sigstore-rust

A Rust implementation of [Sigstore](https://sigstore.dev) for signing and verifying software artifacts.

## Overview

This workspace provides a modular Rust implementation of the Sigstore ecosystem, enabling keyless code signing and verification. Sigstore eliminates the need for long-lived signing keys by binding signatures to OpenID Connect identities and recording them in an immutable transparency log.

## Crates

| Crate | Description |
|-------|-------------|
| [`sigstore-sign`](crates/sigstore-sign) | High-level signing API |
| [`sigstore-verify`](crates/sigstore-verify) | High-level verification API |
| [`sigstore-trust-root`](crates/sigstore-trust-root) | Trusted root management |
| [`sigstore-bundle`](crates/sigstore-bundle) | Sigstore bundle format handling |
| [`sigstore-oidc`](crates/sigstore-oidc) | OpenID Connect authentication |
| [`sigstore-fulcio`](crates/sigstore-fulcio) | Fulcio certificate authority client |
| [`sigstore-rekor`](crates/sigstore-rekor) | Rekor transparency log client |
| [`sigstore-tsa`](crates/sigstore-tsa) | RFC 3161 timestamp authority client |
| [`sigstore-tuf`](crates/sigstore-tuf) | The Update Framework (TUF) client |
| [`sigstore-cache`](crates/sigstore-cache) | Flexible caching support |
| [`sigstore-merkle`](crates/sigstore-merkle) | RFC 6962 Merkle tree verification |
| [`sigstore-crypto`](crates/sigstore-crypto) | Cryptographic primitives |
| [`sigstore-types`](crates/sigstore-types) | Core types and data structures |

## Installation

Add the crates you need to your `Cargo.toml`:

```toml
[dependencies]
# For verification only
sigstore-verify = "0.11"
sigstore-trust-root = "0.11"
sigstore-types = "0.11"

# For signing
sigstore-sign = "0.11"
sigstore-oidc = "0.11"
```

## Usage

### Verifying a Signature

```rust
use sigstore_verify::{Verifier, VerificationPolicy};
use sigstore_trust_root::TrustedRoot;

// Load the trusted root via TUF (recommended - ensures up-to-date trust material)
let root = TrustedRoot::production().await?;
let verifier = Verifier::new(&root);

// Parse the bundle (contains signature, certificate, transparency log entry)
let bundle: sigstore_types::Bundle = serde_json::from_str(&bundle_json)?;

// Authorize the expected signer, not just any valid Sigstore identity.
let policy = VerificationPolicy::default()
    .require_issuer("https://token.actions.githubusercontent.com")
    .require_identity("https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/tags/v1.0.0");
verifier.verify(artifact_bytes, &bundle, &policy)?;
```

### Signing an Artifact

```rust
use sigstore_sign::{SigningContext, SigningConfig};

let endpoints = sigstore_trust_root::SigningConfig::production().await?;
let config = SigningConfig::from_tuf_config(&endpoints)?;
let token = sigstore_oidc::get_identity_token(config.oidc_url.as_deref()).await?;
let signer = SigningContext::with_config(config).signer(token);

// Sign the artifact - returns a Sigstore bundle
let bundle = signer.sign(artifact_bytes).await?;

// Save the bundle
let bundle_json = serde_json::to_string_pretty(&bundle)?;
```

## Examples

### Sign and verify an artifact locally

```bash
# Sign the README.md file
cargo run -p sigstore-sign --features browser --example sign_blob -- README.md -o README.md.sigstore.json

# Verify with our tool
cargo run -p sigstore-verify --example verify_bundle -- README.md README.md.sigstore.json

# You can also verify with cosign
cosign verify-blob --bundle README.md.sigstore.json \
    --certificate-identity $INSERT_YOUR_EMAIL \
    --certificate-oidc-issuer https://github.com/login/oauth \
    README.md
```

### Verify a Bundle from GitHub

You can verify Sigstore bundles from GitHub releases:

```sh
# 1. Download a release artifact and its Sigstore bundle
curl -LO https://github.com/sigstore/cosign/releases/download/v3.0.2/cosign_checksums.txt
curl -LO https://github.com/sigstore/cosign/releases/download/v3.0.2/cosign_checksums.txt.sigstore.json

# 2. Verify the bundle (cryptographic verification without identity policy)
cargo run -p sigstore-verify --example verify_bundle -- \
    cosign_checksums.txt cosign_checksums.txt.sigstore.json

# 3. Or verify with identity policy (this release was signed with Google's keyless signer)
cargo run -p sigstore-verify --example verify_bundle -- \
    --identity "keyless@projectsigstore.iam.gserviceaccount.com" \
    --issuer "https://accounts.google.com" \
    cosign_checksums.txt cosign_checksums.txt.sigstore.json
```

## Architecture

```text
┌───────────────────────────────────────────────────────────────────────┐
│                           Application Layer                           │
├───────────────────────┬───────────────────────┬───────────────────────┤
│     sigstore-sign     │    sigstore-verify    │  sigstore-trust-root  │
├───────────────────────┴───────────────┬───────┴───────────────────────┤
│            sigstore-bundle            │         sigstore-oidc         │
├─────────────────┬─────────────────┬───┴─────────────┬─────────────────┤
│ sigstore-fulcio │ sigstore-rekor  │  sigstore-tsa   │  sigstore-tuf   │
├─────────────────┴─────┬───────────┴───────────┬─────┴─────────────────┤
│    sigstore-crypto    │    sigstore-merkle    │    sigstore-cache     │
├───────────────────────┴───────────────────────┴───────────────────────┤
│                            sigstore-types                             │
└───────────────────────────────────────────────────────────────────────┘
```

## How Sigstore Works

1. **Keyless Signing**: Instead of managing long-lived keys, signers authenticate with an OIDC provider (GitHub, Google, etc.)
2. **Short-lived Certificates**: Fulcio issues a certificate valid for ~10 minutes, binding the OIDC identity to an ephemeral key
3. **Transparency Log**: The signature is recorded in Rekor, providing a tamper-evident audit trail
4. **Verification**: Verifiers check the certificate chain, signature, and transparency log entry against the trusted root

## Features

- Full Sigstore bundle support (v0.1, v0.2, v0.3 formats)
- Keyless signing with OIDC authentication
- Certificate chain validation against Fulcio CA
- Transparency log verification (checkpoints, inclusion proofs, SETs)
- RFC 3161 timestamp support
- Identity-based verification policies
- Ambient credential detection for CI/CD environments

## Cryptography

This library uses [aws-lc-rs](https://github.com/aws/aws-lc-rs) as its cryptographic backend. AWS-LC is a general-purpose cryptographic library maintained by AWS, based on code from BoringSSL. It provides:

- ECDSA (P-256, P-384) signature verification and signing
- Ed25519 signature support
- SHA-256/SHA-384/SHA-512 hashing
- X.509 certificate parsing and validation

AWS-LC has a [FIPS 140-3 validated module](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4816).
This workspace does not enable a FIPS build by default and does not claim FIPS
validation for sigstore-rust. Compliance depends on the exact module build,
configuration, platform, and approved operations.

## Minimum Supported Rust Version

Rust 1.86 or later (checked in CI for the locked dependency set on Linux).

## License

Apache-2.0; see [LICENSE](LICENSE).
