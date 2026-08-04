# sigstore-rekor

Rekor transparency-log client for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Supported APIs

| Capability | Rekor v1 | Rekor v2 |
|---|---:|---:|
| Submit artifact signatures | Yes (`hashedrekord/0.0.1`) | Yes (`hashedrekord/0.0.2`) |
| Submit DSSE envelopes | Yes (`dsse/0.0.1`) | Yes, as `hashedrekord/0.0.2` over the DSSE PAE |
| Lookup and search | Yes | Not provided by Rekor v2 |
| Log information/public key endpoints | Yes | Not provided by Rekor v2 |
| Checkpoint and tile reads | No | Yes |

Rekor v2 deliberately has no `dsse/0.0.2` entry type. A DSSE client logs the
digest of `PAE(payloadType, payload)` and the envelope signature as a
`hashedrekord/0.0.2` entry.

Rekor v2 also has no integrated time or Signed Entry Timestamp. A signing client
must obtain an RFC 3161 timestamp and include it in the bundle.

## V1 example

```rust,no_run
use sigstore_rekor::RekorClient;

# async fn example() -> Result<(), sigstore_rekor::Error> {
let client = RekorClient::public();
let log = client.get_log_info().await?;
println!("tree size: {}", log.tree_size);
# Ok(())
# }
```

## V2 write example

```rust,no_run
use sigstore_rekor::{HashedRekordV2, RekorClient, RekorV2KeyDetails};
use sigstore_types::{DerCertificate, Sha256Hash, SignatureBytes};

# async fn example(
#     digest: Sha256Hash,
#     signature: SignatureBytes,
#     certificate: DerCertificate,
# ) -> Result<(), sigstore_rekor::Error> {
let request = HashedRekordV2::new_with_certificate(
    &digest,
    &signature,
    &certificate,
    RekorV2KeyDetails::PkixEcdsaP256Sha256,
);
let entry = RekorClient::public_v2().create_entry_v2(request).await?;
println!("log index: {}", entry.log_index);
# Ok(())
# }
```

`create_entry_v2` returns the protobuf-compatible
`sigstore_types::TransparencyLogEntry` directly. It does not convert the v2
response through the differently encoded v1 response types.

## V2 checkpoint and tile reads

```rust,no_run
use sigstore_rekor::RekorClient;
use std::num::NonZeroU8;

# async fn example() -> Result<(), sigstore_rekor::Error> {
let client = RekorClient::public_v2();
let checkpoint = client.get_checkpoint().await?;
let full_tile = client.get_tile(0, 12, None).await?;
let partial_entries = client
    .get_entry_bundle(4, NonZeroU8::new(17))
    .await?;
println!("checkpoint tree size: {}", checkpoint.tree_size);
println!("tile bytes: {}", full_tile.as_bytes().len());
println!("entry bytes: {}", partial_entries.as_bytes().len());
# Ok(())
# }
```

Checkpoint responses are parsed as `sigstore_types::Checkpoint`; parsing does
not verify their signatures. Tile and entry-bundle wrappers retain their
coordinates and raw C2SP wire bytes.
Inclusion and consistency proofs are computed by consumers from those tiles; Rekor v2 does
not expose the v1 online-verification endpoints.

## API selection

`RekorClient::new`, `public`, and `staging` construct v1 clients.
`RekorClient::new_v2`, `public_v2`, and `staging_v2` construct v2 clients.
Version-specific operations fail locally when called on the wrong client.
For signing, prefer endpoints discovered from Sigstore's TUF `SigningConfig`
rather than hard-coded public URLs.
