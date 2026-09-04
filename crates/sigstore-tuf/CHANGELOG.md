# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.12.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-tuf-v0.11.0...sigstore-tuf-v0.12.0) - 2026-09-04

### Fixed

- *(tuf)* reverify cached delegated roles ([#173](https://github.com/sigstore/sigstore-rust/pull/173))
- *(tuf)* keep wildcards within path segments ([#174](https://github.com/sigstore/sigstore-rust/pull/174))

### Other

- *(tuf)* [**breaking**] remove obsolete target accessors ([#190](https://github.com/sigstore/sigstore-rust/pull/190))
- *(crypto)* [**breaking**] clarify SPKI constructor names ([#178](https://github.com/sigstore/sigstore-rust/pull/178))
- tuf, crypto: Support ML-DSA ([#142](https://github.com/sigstore/sigstore-rust/pull/142))

## [0.10.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-tuf-v0.9.0...sigstore-tuf-v0.10.0) - 2026-06-29

### Added

- *(trust-root)* [**breaking**] support trusting custom Sigstore instances over TUF ([#136](https://github.com/sigstore/sigstore-rust/pull/136))

## [0.9.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-tuf-v0.8.0...sigstore-tuf-v0.9.0) - 2026-06-17

### Other

- add crate README ([#131](https://github.com/sigstore/sigstore-rust/pull/131))
- use tempfile and write atomically ([#128](https://github.com/sigstore/sigstore-rust/pull/128))
