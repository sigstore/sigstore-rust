# sigstore-bundle

Bundle format handling for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate handles Sigstore bundle creation, parsing, and validation. A Sigstore bundle is a self-contained package that includes a signature, verification material (certificates or public keys), and transparency log entries.

## Features

- **Bundle parsing**: Load bundles from JSON (v0.1, v0.2, v0.3 formats)
- **Bundle creation**: Build v0.3 bundles with type-safe `BundleV03`
- **Validation**: Structural validation of bundle contents
- **Version handling**: Support for multiple bundle format versions
- **Media type detection**: Automatic format detection from media type

## Bundle Versions

| Version | Media Type | Notes |
|---------|------------|-------|
| 0.1 | `application/vnd.dev.sigstore.bundle+json;version=0.1` | Legacy format |
| 0.2 | `application/vnd.dev.sigstore.bundle+json;version=0.2` | Added DSSE support |
| 0.3 | `application/vnd.dev.sigstore.bundle.v0.3+json` | Current format |

## Usage

```rust
use sigstore_bundle::{BundleV03, ValidationOptions};
use sigstore_types::Bundle;

// Parse a bundle
let bundle: Bundle = serde_json::from_str(bundle_json)?;

// Validate structure
let options = ValidationOptions::default();
sigstore_bundle::validate(&bundle, &options)?;

// Build a v0.3 bundle (type-safe: certificate chains not allowed)
let bundle = BundleV03::with_certificate_and_signature(cert_der, signature, artifact_hash)
    .with_tlog_entry(entry)
    .into_bundle();
```

## Related Crates

Used by:

- [`sigstore-verify`](../sigstore-verify) - Parses bundles for verification
- [`sigstore-sign`](../sigstore-sign) - Creates bundles after signing

## License

Apache-2.0
