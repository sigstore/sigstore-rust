# sigstore-sign

Sigstore signature creation for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate provides high-level APIs for creating Sigstore signatures. It orchestrates the keyless signing flow: OIDC authentication, certificate issuance from Fulcio, signing, transparency log submission to Rekor, and optional timestamping.

## Features

- **Keyless signing**: Sign artifacts using OIDC identity (no long-lived keys)
- **Bundle creation**: Produces standard Sigstore bundles
- **Transparency logging**: Automatic submission to Rekor
- **Timestamping**: Optional RFC 3161 timestamps for long-term validity
- **Multiple content types**: Support for blobs and DSSE attestations

## Signing Flow

1. Authenticate with OIDC provider (or use ambient credentials)
2. Generate ephemeral key pair
3. Request certificate from Fulcio
4. Sign the artifact
5. Submit to Rekor transparency log
6. Optionally request timestamp from TSA
7. Package everything into a Sigstore bundle

## Usage

```rust
use sigstore_sign::{SigningContext, Attestation, AttestationSubject};
use sigstore_oidc::IdentityToken;
use sigstore_types::Sha256Hash;

// Create a signing context for production
let context = SigningContext::production();

// Get an identity token (from OIDC provider)
let token = IdentityToken::new("your-identity-token".to_string());

// Create a signer
let signer = context.signer(token);

// Sign artifact bytes
let artifact = b"hello world";
let bundle = signer.sign(artifact).await?;

// Or sign with a pre-computed digest (for large files)
let digest = Sha256Hash::from_hex("b94d27b9...")?;
let bundle = signer.sign(digest).await?;

// Or stream without loading the artifact into memory
let file = std::fs::File::open("large-artifact.tar.gz")?;
let bundle = signer.sign_reader(file).await?;

// Runtime-independent async readers are supported as well
let bundle = signer.sign_async_reader(async_reader).await?;

// Sign an in-toto attestation (DSSE envelope)
let subject = AttestationSubject::new("artifact.tar.gz", digest);
let attestation = Attestation::new("https://slsa.dev/provenance/v1")
    .with_subject(subject)
    .with_predicate(serde_json::json!({"key": "value"}));
let bundle = signer.sign_attestation(attestation).await?;

// Write bundle to file
std::fs::write("artifact.sigstore.json", bundle.to_json_pretty()?)?;
```

## Configuration

```rust
use sigstore_sign::SigningContext;

// Production environment
let context = SigningContext::production();

// Staging environment
let context = SigningContext::staging();
```

## Related Crates

- [`sigstore-verify`](../sigstore-verify) - Verify signatures created by this crate

## License

BSD-3-Clause
