# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.1](https://github.com/sigstore/sigstore-rust/compare/sigstore-types-v0.8.0...sigstore-types-v0.8.1) - 2026-06-12

### Other

- harden message-signature verification, drop digest leak ([#119](https://github.com/sigstore/sigstore-rust/pull/119))
- Various improvements ([#109](https://github.com/sigstore/sigstore-rust/pull/109))

## [0.8.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-types-v0.7.0...sigstore-types-v0.8.0) - 2026-05-21

### Other

- Replace direct chrono usage with jiff ([#90](https://github.com/sigstore/sigstore-rust/pull/90))

## [0.6.6](https://github.com/sigstore/sigstore-rust/compare/sigstore-types-v0.6.5...sigstore-types-v0.6.6) - 2026-04-29

### Fixed

- *(sigstore-types)* handle missing optional fields in cosign v3 bundles ([#82](https://github.com/sigstore/sigstore-rust/pull/82))

## [0.6.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-types-v0.5.0...sigstore-types-v0.6.0) - 2025-12-08

### Other

- improve types and add interop test workflow ([#9](https://github.com/wolfv/sigstore-rust/pull/9))

## [0.4.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-types-v0.3.0...sigstore-types-v0.4.0) - 2025-11-28

### Other

- add missing file
- introduce new artifact api

## [0.3.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-types-v0.2.0...sigstore-types-v0.3.0) - 2025-11-28

### Other

- make all interfaces more type safe
- unify certificate encoding
- improve sign / verify flow, add conda specific test
- more cleanup of functions

## [0.2.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-types-v0.1.1...sigstore-types-v0.2.0) - 2025-11-27

### Other

- more dead code removal
- format
- remove duplicated types, add license and readme files
