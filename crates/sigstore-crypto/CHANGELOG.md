# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.14.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-crypto-v0.13.0...sigstore-crypto-v0.14.0) - 2026-09-25

### Added

- *(crypto)* read the deprecated Fulcio GitHub Actions claims ([#252](https://github.com/sigstore/sigstore-rust/pull/252))
- *(crypto)* [**breaking**] parse the Fulcio CI claims and expose the verified certificate ([#250](https://github.com/sigstore/sigstore-rust/pull/250))

### Other

- *(types)* [**breaking**] 1.0 naming and conversion conventions ([#247](https://github.com/sigstore/sigstore-rust/pull/247))
- *(crypto)* [**breaking**] opaque key pairs and extensible algorithm enums ([#246](https://github.com/sigstore/sigstore-rust/pull/246))
- *(types)* [**breaking**] make wire types and enums extensible ([#236](https://github.com/sigstore/sigstore-rust/pull/236))
- *(crypto)* single OID match in key_algorithm ([#238](https://github.com/sigstore/sigstore-rust/pull/238))

## [0.13.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-crypto-v0.12.0...sigstore-crypto-v0.13.0) - 2026-09-23

### Fixed

- *(types)* [**breaking**] keep checkpoint fields consistent with the signed note ([#229](https://github.com/sigstore/sigstore-rust/pull/229))
- [**breaking**] restore fixes dropped from the pre-1.0 stack (#214–#219) ([#226](https://github.com/sigstore/sigstore-rust/pull/226))

## [0.12.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-crypto-v0.11.0...sigstore-crypto-v0.12.0) - 2026-09-23

### Added

- *(artifact)* [**breaking**] stream artifacts from sync and async readers ([#185](https://github.com/sigstore/sigstore-rust/pull/185))

### Fixed

- *(crypto)* validate and share algorithm resolution ([#207](https://github.com/sigstore/sigstore-rust/pull/207))
- *(crypto)* use explicit-scheme SPKI constructor in signing test ([#188](https://github.com/sigstore/sigstore-rust/pull/188))
- *(sign)* keep unbounded hashing and signing from starving the async executor (TOB-SIGSTORE-8) ([#183](https://github.com/sigstore/sigstore-rust/pull/183))
- *(verify)* [**breaking**] remove clock skew, and use `jiff` Timestamp in the interfaces ([#164](https://github.com/sigstore/sigstore-rust/pull/164))

### Other

- *(release)* repair API examples, licensing and trust bootstrap guidance ([#206](https://github.com/sigstore/sigstore-rust/pull/206))
- *(release)* tighten dependencies, MSRV and feature checks ([#202](https://github.com/sigstore/sigstore-rust/pull/202))
- *(types)* [**breaking**] deserialize semantic bundle values eagerly ([#196](https://github.com/sigstore/sigstore-rust/pull/196))
- *(artifact)* [**breaking**] make artifact digests typed ([#184](https://github.com/sigstore/sigstore-rust/pull/184))
- *(crypto)* [**breaking**] clarify SPKI constructor names ([#178](https://github.com/sigstore/sigstore-rust/pull/178))
- *(trust-root)* [**breaking**] consolidate transparency key getters and align TimeRange semantics ([#159](https://github.com/sigstore/sigstore-rust/pull/159))
- tuf, crypto: Support ML-DSA ([#142](https://github.com/sigstore/sigstore-rust/pull/142))
- *(crypto)* [**breaking**] unify signature verification behind VerificationKey (TOB-SIGSTORE-6) ([#168](https://github.com/sigstore/sigstore-rust/pull/168))

## [0.9.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-crypto-v0.8.0...sigstore-crypto-v0.9.0) - 2026-06-17

### Other

- harden message-signature verification, drop digest leak ([#119](https://github.com/sigstore/sigstore-rust/pull/119))
- support sha256/384/512 digests, fail closed on unsupported signing schemes, and add `KeyAlgorithm` ([#109](https://github.com/sigstore/sigstore-rust/pull/109))
- If a Fulcio OID is found, it must be parseable ([#108](https://github.com/sigstore/sigstore-rust/pull/108))

## [0.8.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-crypto-v0.7.0...sigstore-crypto-v0.8.0) - 2026-05-21

### Other

- update Cargo.toml dependencies

## [0.7.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-crypto-v0.6.6...sigstore-crypto-v0.7.0) - 2026-05-13

### Other

- update Cargo.toml dependencies

## [0.6.4](https://github.com/sigstore/sigstore-rust/compare/sigstore-crypto-v0.6.3...sigstore-crypto-v0.6.4) - 2026-03-06

### Fixed

- be more strict about unknown key types and verification ([#70](https://github.com/sigstore/sigstore-rust/pull/70))

## [0.4.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-crypto-v0.3.0...sigstore-crypto-v0.4.0) - 2025-11-28

### Other

- introduce new artifact api

## [0.3.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-crypto-v0.2.0...sigstore-crypto-v0.3.0) - 2025-11-28

### Other

- make all interfaces more type safe
- remove more types
- encode more certificates properly
- unify certificate encoding
- improve sign / verify flow, add conda specific test
- more cleanup of functions

## [0.2.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-crypto-v0.1.1...sigstore-crypto-v0.2.0) - 2025-11-27

### Other

- format
- remove duplicated types, add license and readme files

## [0.1.1](https://github.com/wolfv/sigstore-rust/compare/sigstore-crypto-v0.1.0...sigstore-crypto-v0.1.1) - 2025-11-27

### Fixed

- fix verification
