# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.14.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-fulcio-v0.13.0...sigstore-fulcio-v0.14.0) - 2026-09-25

### Added

- unify and set default User-Agent across all HTTP clients ([#256](https://github.com/sigstore/sigstore-rust/pull/256))

### Fixed

- *(cache)* [**breaking**] scope cache keys by service URL ([#241](https://github.com/sigstore/sigstore-rust/pull/241))

### Other

- *(fulcio)* [**breaking**] typed responses, private requests and a client builder ([#248](https://github.com/sigstore/sigstore-rust/pull/248))
- *(oidc)* [**breaking**] keep secrets out of the public API and make types extensible ([#239](https://github.com/sigstore/sigstore-rust/pull/239))

## [0.13.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-fulcio-v0.12.0...sigstore-fulcio-v0.13.0) - 2026-09-23

### Fixed

- *(fulcio)* [**breaking**] parse wildcard issuers in the Fulcio configuration ([#228](https://github.com/sigstore/sigstore-rust/pull/228))
- [**breaking**] restore fixes dropped from the pre-1.0 stack (#214–#219) ([#226](https://github.com/sigstore/sigstore-rust/pull/226))

## [0.12.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-fulcio-v0.11.0...sigstore-fulcio-v0.12.0) - 2026-09-23

### Other

- *(release)* repair API examples, licensing and trust bootstrap guidance ([#206](https://github.com/sigstore/sigstore-rust/pull/206))
- *(release)* tighten dependencies, MSRV and feature checks ([#202](https://github.com/sigstore/sigstore-rust/pull/202))

## [0.6.2](https://github.com/prefix-dev/sigstore-rust/compare/sigstore-fulcio-v0.6.1...sigstore-fulcio-v0.6.2) - 2026-02-04

### Other

- add native-tls feature, bump reqwest ([#51](https://github.com/prefix-dev/sigstore-rust/pull/51))

## [0.3.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-fulcio-v0.2.0...sigstore-fulcio-v0.3.0) - 2025-11-28

### Fixed

- fix clippy warnings

### Other

- add sigstore-cache
- remove more types
- encode more certificates properly

## [0.2.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-fulcio-v0.1.1...sigstore-fulcio-v0.2.0) - 2025-11-27

### Other

- remove duplicated types, add license and readme files

## [0.1.1](https://github.com/wolfv/sigstore-rust/compare/sigstore-fulcio-v0.1.0...sigstore-fulcio-v0.1.1) - 2025-11-27

### Fixed

- fix publishing

### Other

- fmt
- hash raw dsse
- initial commit
