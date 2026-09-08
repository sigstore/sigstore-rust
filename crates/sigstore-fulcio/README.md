# sigstore-fulcio

Fulcio certificate authority client for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate provides a client for Fulcio, Sigstore's certificate authority. Fulcio issues short-lived code signing certificates based on OIDC identity tokens, enabling keyless signing where the signer's identity is bound to their OIDC identity rather than a long-lived private key.

## Features

- **Certificate signing requests**: Generate and submit CSRs to Fulcio
- **Certificate retrieval**: Obtain signed certificates and certificate chains
- **Proof of possession**: Challenge-response for key ownership verification
- **Detached SCTs**: Support for Signed Certificate Timestamps

## How It Works

1. Signer authenticates with an OIDC provider
2. Signer generates an ephemeral key pair
3. Signer submits a CSR with the OIDC token to Fulcio
4. Fulcio verifies the token and issues a short-lived certificate
5. Certificate embeds the OIDC identity (email, subject, issuer)

## Usage

```rust
use sigstore_fulcio::FulcioClient;

let client = FulcioClient::production();
let certificate = client
    .request_certificate(&public_key, &oidc_token, &proof_of_possession)
    .await?;
```

## Related Crates

Used by:

- [`sigstore-sign`](../sigstore-sign) - Requests certificates during signing

## License

Apache-2.0
