# sigstore-sign

Sigstore signature creation for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate provides high-level APIs for creating Sigstore signatures. It orchestrates the keyless signing flow: OIDC authentication, certificate issuance from Fulcio, signing, transparency log submission to Rekor, and optional timestamping. Instances that run no transparency log, such as GitHub's artifact attestation instance, are supported as well; their bundles carry an RFC 3161 timestamp instead of a log entry.

## Features

- **Keyless signing**: Sign artifacts using OIDC identity (no long-lived keys)
- **Bundle creation**: Produces standard Sigstore bundles
- **Transparency logging**: Automatic submission to Rekor, or none for instances that run no log
- **Timestamping**: RFC 3161 timestamps for long-term validity (required with Rekor v2 or without a log)
- **Multiple content types**: Support for blobs and DSSE attestations

## Signing Flow

1. Authenticate with OIDC provider (or use ambient credentials)
2. Generate ephemeral key pair
3. Request certificate from Fulcio
4. Sign the artifact
5. Submit to Rekor transparency log (skipped for instances that run no log)
6. Request timestamp from TSA (optional with Rekor v1, required otherwise)
7. Package everything into a Sigstore bundle

## Usage

```rust
use sigstore_sign::{Attestation, SigningContext};
use sigstore_types::Sha256Hash;

// Fetch the public-good signing config through TUF and authenticate with its
// OIDC provider (browser with the `browser` feature, otherwise a pasted code)
let signer = SigningContext::production().await?.authenticate().await?;

// Or use an identity token obtained elsewhere, e.g. ambient CI credentials
let token = sigstore_oidc::IdentityToken::detect_ambient()
    .await?
    .ok_or("no ambient credentials")?;
let signer = SigningContext::production().await?.signer(token);

// Sign artifact bytes
let bundle = signer.sign(b"hello world").await?;

// Or sign a pre-computed digest (for large files)
let digest = Sha256Hash::from_hex("b94d27b9...")?;
let bundle = signer.sign(digest).await?;

// Or stream without loading the artifact into memory
let file = std::fs::File::open("large-artifact.tar.gz")?;
let bundle = signer.sign_reader(file).await?;

// Runtime-independent async readers are supported as well
let bundle = signer.sign_async_reader(async_reader).await?;

// Sign an in-toto attestation (DSSE envelope)
let attestation = Attestation::new(
    "https://slsa.dev/provenance/v1",
    serde_json::json!({"key": "value"}),
)
.add_subject("artifact.tar.gz", digest);
let bundle = signer.sign_attestation(attestation).await?;

// Write bundle to file
std::fs::write("artifact.sigstore.json", bundle.to_json_pretty()?)?;
```

## Configuration

```rust
use sigstore_sign::{reqwest, SigningContext, SigningServices, SigstoreInstance};

// Well-known instances, with signing configs fetched through TUF
let context = SigningContext::staging().await?;
let context = SigningContext::for_instance(SigstoreInstance::PublicGood).await?;

// The embedded snapshot, without contacting TUF (may be stale)
let context = SigningContext::from_embedded(SigstoreInstance::PublicGood)?;

// Explicit services
let services = SigningServices::new("https://fulcio.example", "https://rekor.example")
    .with_tsa_url("https://tsa.example/api/v1/timestamp")
    .with_oidc_url("https://oidc.example/auth");
let context = SigningContext::new(services)
    // Timeouts, proxies and TLS settings are configured on the HTTP client
    .with_http_client(reqwest::Client::builder().build()?);
```

### Signing without a transparency log

GitHub's artifact attestation instance, which `actions/attest` uses for
private and internal repositories, runs no transparency log so that nothing
about the repository is published. It also publishes no signing config
through TUF, so `SigningContext::for_instance(SigstoreInstance::GitHub)`
uses the crate's embedded signing config without contacting TUF. Its Fulcio
only accepts GitHub Actions identity tokens.

```rust
use sigstore_sign::{SigningContext, SigningServices, SigstoreInstance};

// GitHub's Fulcio and TSA, no Rekor
let context = SigningContext::for_instance(SigstoreInstance::GitHub).await?;

// Another instance without a log: explicit Fulcio and TSA
let services = SigningServices::without_transparency_log(
    "https://fulcio.example",
    "https://tsa.example/api/v1/timestamp",
);
```

Bundles signed this way carry an RFC 3161 timestamp as the only evidence of
when the signature was made, and no log entry. Verifiers must trust the
instance's TSA and opt in to accepting such bundles, for example with
`sigstore_verify::VerificationPolicy::skip_tlog_unsafe`. A signing config
fetched through TUF is never used without a log: `from_signing_config`
rejects a config that lists no eligible Rekor endpoint.

For Tokio files/streams, enable `tokio-util`'s `compat` feature and call
`TokioAsyncReadCompatExt::compat()` before passing the reader to the async API.

## Related Crates

- [`sigstore-verify`](../sigstore-verify) - Verify signatures created by this crate

## License

Apache-2.0
