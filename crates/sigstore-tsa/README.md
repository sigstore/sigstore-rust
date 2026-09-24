# sigstore-tsa

RFC 3161 Time-Stamp Protocol client for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate implements the Time-Stamp Protocol as specified in RFC 3161. It provides functionality to request timestamps from Time-Stamp Authorities (TSAs) and verify timestamp responses.

Timestamps provide trusted third-party evidence of when a signature was created, which is essential for verifying signatures after the signing certificate has expired.

## Features

- **Timestamp requests**: Create and send RFC 3161 timestamp requests
- **Response parsing**: Parse and validate timestamp responses
- **Timestamp verification**: Verify timestamp tokens against TSA certificates
- **Multiple TSAs**: Built-in support for Sigstore TSA and FreeTSA

HTTP clients require the `client` feature, enabled by the default `rustls` feature.
Use `default-features = false` for offline ASN.1 parsing and timestamp verification
without reqwest or Tokio. `native-tls` enables the client with the alternative TLS backend.

## Usage

```rust
use sigstore_tsa::TimestampClient;

// The TSA URL comes from the Sigstore instance's signing config
let client = TimestampClient::new("https://timestamp.sigstore.dev/api/v1/timestamp")?;
let timestamp_token = client.timestamp_signature(&signature).await?;
```

Verification is exposed as `verify_timestamp_for_authority`, which checks a
token against one timestamp authority from the trusted root. The RFC 3161
ASN.1 structures are internal to the crate.

## Related Crates

Used by:

- [`sigstore-sign`](../sigstore-sign) - Requests timestamps during signing
- [`sigstore-verify`](../sigstore-verify) - Verifies timestamps in bundles

## License

Apache-2.0
