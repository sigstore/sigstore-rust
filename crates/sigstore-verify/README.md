# sigstore-verify

Sigstore signature verification for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate provides high-level APIs for verifying Sigstore signatures. It handles the complete verification flow: bundle parsing, certificate chain validation, signature verification, transparency log verification, and identity policy enforcement.

## Features

- **Bundle verification**: Verify standard Sigstore bundles
- **Certificate validation**: X.509 chain validation against Fulcio CA
- **Transparency log verification**: Checkpoint signatures, inclusion proofs, SETs
- **Timestamp verification**: RFC 3161 timestamp validation
- **Identity policies**: Verify signer identity claims (issuer, subject, etc.)

## Verification Steps

1. Parse and validate bundle structure
2. Verify certificate chain against trusted root
3. Verify signature over artifact
4. Verify transparency log entry (checkpoint, inclusion proof, or SET)
5. Verify timestamps if present
6. Check identity against policy (optional)

## Verifier construction

`Verifier::new(&root)?` prepares Rekor/CT keyrings and Fulcio trust anchors before
reading artifacts. Invalid certificates, keys, duplicate log IDs and reversed
validity windows are errors at construction. Unsupported configured keys must be
removed explicitly rather than silently ignored. Key/authority activation times
are still checked when verifying, so long-lived verifiers do not freeze time.

## Verification results

`VerificationResult` is created only by successful verification and exposes
read-only accessors. `identity()` and `issuer()` are certificate claims;
`certificate_verified()`, `sct_verified()`, `tlog_verified()` and
`identity_policy_checked()` describe what was actually checked.
`verified_timestamps()` excludes unsigned time hints. Relaxed policies must not
be treated as equivalent to full certificate and log verification.

## Authorization

`VerificationPolicy` has no default. Prefer `VerificationPolicy::new(identity, issuer)`
to authorize the expected signer. `any_identity()` is an explicit opt-in to
cryptographic verification without signer authorization. The example CLI likewise
requires an identity/issuer restriction or `--allow-any-identity`.

## Usage

```rust
use sigstore_verify::{verify, Verifier, VerificationPolicy};
use sigstore_trust_root::{TrustedRoot, TufConfig};
use sigstore_types::{Artifact, Bundle, Sha256Hash};

let bundle: Bundle = serde_json::from_str(bundle_json)?;
let policy = VerificationPolicy::any_identity();

// Actively choose the Sigstore instance and fetch its root through TUF.
let root = TrustedRoot::from_tuf(TufConfig::production()).await?;

// Verify with raw artifact bytes
let artifact_bytes = b"hello world";
let result = verify(artifact_bytes.as_slice(), &bundle, &policy, &root)?;

// Or verify with pre-computed SHA-256 digest (useful for large files)
let digest = Sha256Hash::from_hex("b94d27b9...")?;
let result = verify(digest, &bundle, &policy, &root)?;

// Or use a Verifier directly; it also offers the same inputs
let verifier = Verifier::new(&root)?;
let result = verifier.verify(artifact_bytes.as_slice(), &bundle, &policy)?;

// Stream a large artifact in constant memory
let file = std::fs::File::open("large-artifact.tar.gz")?;
let result = verifier.verify_reader(file, &bundle, &policy)?;

// Runtime-independent futures_io::AsyncRead is also supported
let result = verifier.verify_async_reader(async_reader, &bundle, &policy).await?;

// Managed-key bundles use the `verify_with_key*` family with the same
// three input shapes: `verify_with_key`, `verify_with_key_reader`,
// `verify_with_key_async_reader`.
```

For Tokio readers, enable `tokio-util`'s `compat` feature and use
`tokio_util::compat::TokioAsyncReadCompatExt::compat()` on the file or stream.
Reader verification rejects message-signature schemes that require the original
bytes (such as Ed25519) before consuming input; use the byte API for those schemes.

For GitHub artifact attestations, choose GitHub's Sigstore instance explicitly
and use the GitHub verification profile:

```rust
use sigstore_trust_root::{SigstoreInstance, TrustedRoot};
use sigstore_verify::{verify, VerificationPolicy};
use sigstore_types::{Bundle, Sha256Hash};

let bundle: Bundle = serde_json::from_str(bundle_json)?;
let artifact_digest = Sha256Hash::from_hex("...")?;

// Fetch GitHub's trusted root over TUF (now supported via the `sigstore-tuf`
// client), or use the embedded copy below for an offline path.
// let root = TrustedRoot::from_tuf(sigstore_trust_root::TufConfig::github()).await?;
let root = TrustedRoot::from_embedded(SigstoreInstance::GitHub)?;
let policy = VerificationPolicy::any_identity().skip_tlog_unsafe().skip_sct();

let result = verify(artifact_digest, &bundle, &policy, &root)?;
```

## Verification Policies

```rust
use sigstore_verify::VerificationPolicy;

// Default policy (verify tlog, timestamps, and certificate chain)
let policy = VerificationPolicy::any_identity();

// Require specific identity and issuer
let policy = VerificationPolicy::any_identity()
    .require_identity("user@example.com")
    .require_issuer("https://accounts.google.com");

// Skip certain verifications (for testing only)
let policy = VerificationPolicy::any_identity()
    .skip_tlog_unsafe()
    .skip_certificate_chain();
```

## Related Crates

- [`sigstore-sign`](../sigstore-sign) - Create signatures to verify with this crate

## License

Apache-2.0
