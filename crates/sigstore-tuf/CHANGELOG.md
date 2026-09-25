# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.14.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-tuf-v0.13.0...sigstore-tuf-v0.14.0) - 2026-09-25

### Added

- unify and set default User-Agent across all HTTP clients ([#256](https://github.com/sigstore/sigstore-rust/pull/256))

### Other

- *(release)* version sigstore-tuf and sigstore-cache independently ([#254](https://github.com/sigstore/sigstore-rust/pull/254))
- *(tsa,oidc,tuf)* [**breaking**] accept caller-configured reqwest clients ([#249](https://github.com/sigstore/sigstore-rust/pull/249))

## [0.13.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-tuf-v0.12.0...sigstore-tuf-v0.13.0) - 2026-09-23

### Fixed

- *(tuf)* [**breaking**] prevent changing metadata after its signed bytes are captured ([#230](https://github.com/sigstore/sigstore-rust/pull/230))

## [0.12.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-tuf-v0.11.0...sigstore-tuf-v0.12.0) - 2026-09-23

### Fixed

- *(tuf)* preserve expired rollback floors and require fresh target authorization ([#198](https://github.com/sigstore/sigstore-rust/pull/198))
- *(tuf)* reverify cached delegated roles ([#173](https://github.com/sigstore/sigstore-rust/pull/173))
- *(tuf)* keep wildcards within path segments ([#174](https://github.com/sigstore/sigstore-rust/pull/174))

### Other

- *(release)* repair API examples, licensing and trust bootstrap guidance ([#206](https://github.com/sigstore/sigstore-rust/pull/206))
- *(release)* tighten dependencies, MSRV and feature checks ([#202](https://github.com/sigstore/sigstore-rust/pull/202))
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
