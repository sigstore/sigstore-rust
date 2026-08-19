# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.12.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-rekor-v0.11.0...sigstore-rekor-v0.12.0) - 2026-08-19

### Fixed

- *(verify)* handle canonical Rekor intoto entries ([#175](https://github.com/sigstore/sigstore-rust/pull/175))
- *(verify)* [**breaking**] remove clock skew, and use `jiff` Timestamp in the interfaces ([#164](https://github.com/sigstore/sigstore-rust/pull/164))

## [0.6.2](https://github.com/prefix-dev/sigstore-rust/compare/sigstore-rekor-v0.6.1...sigstore-rekor-v0.6.2) - 2026-02-04

### Other

- add native-tls feature, bump reqwest ([#51](https://github.com/prefix-dev/sigstore-rust/pull/51))

## [0.5.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-rekor-v0.4.0...sigstore-rekor-v0.5.0) - 2025-12-01

### Added

- Add SigningConfig support and V2 bundle fixes ([#6](https://github.com/wolfv/sigstore-rust/pull/6))

## [0.3.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-rekor-v0.2.0...sigstore-rekor-v0.3.0) - 2025-11-28

### Other

- add sigstore-cache
- make all interfaces more type safe
- remove more types
- remove certifactePem
- improve sign / verify flow, add conda specific test

## [0.2.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-rekor-v0.1.1...sigstore-rekor-v0.2.0) - 2025-11-27

### Other

- remove duplicated types, add license and readme files
