# sigstore-tuf

A pure-Rust implementation of [The Update Framework (TUF)](https://theupdateframework.io/) for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate is a focused TUF client built for Sigstore's needs, aligned with `python-tuf` (sigstore-python) and `go-tuf` (sigstore-go) and inspired by `tough` — but deliberately interoperable with **all** of the ecosystem's repositories, including those produced by `tuf-on-ci` / `securesystemslib` such as GitHub's (`https://tuf-repo.github.com`).

## Features

- **Full client workflow**: root chaining → timestamp → snapshot → top-level targets, with all verification funneled through one audited state machine
- **Delegated targets discovery**: pre-order DFS with `terminating` handling and path / hash-prefix matching
- **Anti-rollback, expiry, and threshold checks**: signature thresholds, version floors, and freeze-attack protection that spans process runs
- **Per-file download bounds**: every fetch carries a per-role `max_length` to cap endless-data attacks
- **Pluggable transport**: the verification core never touches the network; HTTP, in-memory, and offline transports are all just `Repository` implementations
- **Write-through caching**: an optional on-disk store receives every *verified* metadata file and is re-verified from the pinned root on the next run, so a tampered cache can never bypass verification

## Why not just use `tough`?

`tough` recomputes each key's TUF key ID over the entire key object (including non-standard fields like `x-tuf-on-ci-keyowner`) and *rejects* metadata whose declared key IDs don't match. That makes it unable to load GitHub's TUF root at all, even though `python-tuf`, `go-tuf`, and `gh attestation` all consume it fine. Per the TUF spec a key ID is an opaque, producer-chosen identifier — there is no requirement that `keyid == hash(key)`. This crate therefore treats **declared key IDs as authoritative** and never recomputes-and-rejects.

A second, subtler interop requirement: TUF signs over **securesystemslib / OLPC canonical JSON**, not RFC 8785 JCS. The two differ in string escaping (notably newlines inside embedded PEM keys) and number handling, so this crate ships its own canonical encoder rather than reuse a JCS implementation.

## Usage

```rust
use sigstore_tuf::{client::Updater, client::HttpRepository, cache::FileStore};

let repo = HttpRepository::new("https://tuf-repo.github.com")?;
let root = std::fs::read("github-root.json")?;
let mut updater = Updater::new(repo, &root)?
    .with_store(FileStore::new("/var/cache/sigstore/github"));
updater.refresh(jiff::Timestamp::now()).await?;

let trusted_root = updater
    .get_target("trusted_root.json", jiff::Timestamp::now())
    .await?;
```

## Cargo Features

- `fetch` (default) — async HTTP transport for fetching remote metadata and targets
- `rustls` (default) — use rustls as the TLS backend
- `native-tls` — use the platform's native TLS backend instead

To use the verification core without any network transport:

```toml
[dependencies]
sigstore-tuf = { version = "0.8", default-features = false }
```

## Architecture

- **`canonical_json`** — TUF-compatible canonical JSON (the bytes signatures cover)
- **`key`** — TUF keys → `sigstore_crypto::VerificationKey`; declared key IDs are authoritative
- **`metadata`** — the signed envelope and the four roles (`root`, `timestamp`, `snapshot`, `targets`)
- **`trusted::TrustedMetadataSet`** — the transport-free verification state machine: signature thresholds, anti-rollback, expiry, and length / hash pinning. This is where the security lives, and it is fully unit-testable.
- **`client`** (feature `fetch`) — an HTTP `Updater` that drives the refresh workflow and downloads / verifies targets
- **`cache`** — write-through on-disk caching (`FileStore`) and an offline `StoreRepository` that re-verifies entirely from cache

## Related Crates

Used by:

- [`sigstore-trust-root`](../sigstore-trust-root) — fetches Sigstore trusted roots over TUF

## License

BSD-3-Clause
