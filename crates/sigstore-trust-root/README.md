# sigstore-trust-root

Sigstore trusted root management and parsing for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate handles parsing and management of Sigstore trusted root bundles. The trusted root contains all cryptographic trust anchors needed for verification: Fulcio CA certificates, Rekor public keys, CT log keys, and TSA certificates.

## Features

- **Trusted root parsing**: Load and parse `trusted_root.json` files
- **TUF support**: Secure fetching via The Update Framework (enabled by default)
- **Embedded roots**: Built-in production, staging, and GitHub trust anchors for offline use
- **Key extraction**: Extract public keys and certificates for verification
- **Validity periods**: Time-based key and certificate validity checking
- **Custom TUF repos**: Support for custom TUF repository URLs

## Trust Anchors

| Component | Purpose |
|-----------|---------|
| Certificate Authorities | Fulcio CA certificates for signing certificate validation |
| Transparency Logs | Rekor public keys for log entry verification |
| CT Logs | Certificate Transparency log keys for SCT verification |
| Timestamp Authorities | TSA certificates for RFC 3161 timestamp verification |

## Usage

```rust
use sigstore_trust_root::{SigstoreInstance, TrustedRoot, TufConfig};

// Fetch via TUF (recommended - ensures up-to-date trust material).
let root = TrustedRoot::from_tuf(TufConfig::production()).await?;

// Use embedded data explicitly when offline or when TUF is unavailable.
let root = TrustedRoot::from_embedded(SigstoreInstance::PublicGood)?;

// Load from file
let root = TrustedRoot::from_file("trusted_root.json")?;
```

### GitHub Artifact Attestations

GitHub artifact attestations use GitHub's own Sigstore instance rather than the
public-good Sigstore root. Choose the GitHub instance explicitly for these
bundles:

```rust
use sigstore_trust_root::{SigstoreInstance, TrustedRoot};

// Preferred API shape once GitHub TUF is compatible with the TUF client.
// let root = TrustedRoot::from_tuf(sigstore_trust_root::TufConfig::github()).await?;

// Temporary explicit fallback while GitHub TUF metadata is not accepted by `tough`.
let root = TrustedRoot::from_embedded(SigstoreInstance::GitHub)?;
```

### Custom TUF Repository

```rust
use sigstore_trust_root::{TrustedRoot, TufConfig};

// Fetch from a custom TUF repository (e.g., for testing)
let config = TufConfig::custom(
    "https://sigstore.github.io/root-signing/",
    include_bytes!("path/to/root.json"),
);
let root = TrustedRoot::from_tuf(config).await?;
```

## Cargo Features

- `tuf` (default) - Enable TUF-based secure fetching of trusted roots

To opt out of TUF support:

```toml
[dependencies]
sigstore-trust-root = { version = "0.1", default-features = false }
```

## Updating the Embedded Data

This crate embeds a snapshot of trust material for the production, staging,
and GitHub Sigstore instances: the TUF `root.json` metadata (under
`repository/`) and the `trusted_root.json` / signing config TUF targets
(under `src/` and `repository/`). To refresh all of them using the crate's
own TUF client, run:

```sh
cargo run -p sigstore-trust-root --example update-embedded-roots
```

The fetched bytes are written verbatim, so `git diff` shows exactly what
changed upstream. A scheduled workflow
([`check-embedded-root.yml`](../../.github/workflows/check-embedded-root.yml))
runs this weekly and files an issue when the embedded data is out of date.

## Related Crates

Used by:

- [`sigstore-verify`](../sigstore-verify) - Provides trust anchors for verification
- [`sigstore-sign`](../sigstore-sign) - Provides service endpoints

## License

BSD-3-Clause
