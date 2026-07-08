# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-trust-root-v0.10.0...sigstore-trust-root-v0.11.0) - 2026-07-08

### Other

- refresh embedded TUF data ([#149](https://github.com/sigstore/sigstore-rust/pull/149))

## [0.10.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-trust-root-v0.9.0...sigstore-trust-root-v0.10.0) - 2026-06-29

### Added

- *(trust-root)* [**breaking**] support trusting custom Sigstore instances over TUF ([#136](https://github.com/sigstore/sigstore-rust/pull/136))

### Other

- update embedded roots ([#141](https://github.com/sigstore/sigstore-rust/pull/141))

## [0.9.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-trust-root-v0.8.0...sigstore-trust-root-v0.9.0) - 2026-06-17

### Other

- bump dependencies ([#127](https://github.com/sigstore/sigstore-rust/pull/127))
- enforce valid_for in key accessors, surface parse errors ([#122](https://github.com/sigstore/sigstore-rust/pull/122))
- use tempfile and write atomically ([#128](https://github.com/sigstore/sigstore-rust/pull/128))
- Add sigstore-tuf crate; bootstrap trusted roots over TUF without tough ([#106](https://github.com/sigstore/sigstore-rust/pull/106))
- refresh embedded TUF data (production root v14 → v15) ([#126](https://github.com/sigstore/sigstore-rust/pull/126))
- add automation for embedded TUF data updates ([#121](https://github.com/sigstore/sigstore-rust/pull/121))

## [0.8.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-trust-root-v0.7.0...sigstore-trust-root-v0.8.0) - 2026-05-21

### Other

- Replace direct chrono usage with jiff ([#90](https://github.com/sigstore/sigstore-rust/pull/90))

## [0.7.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-trust-root-v0.6.6...sigstore-trust-root-v0.7.0) - 2026-05-13

### Added

- trust root update and dependency update ([#85](https://github.com/sigstore/sigstore-rust/pull/85))

### Other

- add github TUF root ([#88](https://github.com/sigstore/sigstore-rust/pull/88))

## [0.6.5](https://github.com/sigstore/sigstore-rust/compare/sigstore-trust-root-v0.6.4...sigstore-trust-root-v0.6.5) - 2026-04-19

### Other

- API for fetching / using the trust root ([#69](https://github.com/sigstore/sigstore-rust/pull/69))

## [0.6.4](https://github.com/sigstore/sigstore-rust/compare/sigstore-trust-root-v0.6.3...sigstore-trust-root-v0.6.4) - 2026-03-06

### Other

- update Cargo.toml dependencies

## [0.5.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-trust-root-v0.4.0...sigstore-trust-root-v0.5.0) - 2025-12-01

### Added

- Add SigningConfig support and V2 bundle fixes ([#6](https://github.com/wolfv/sigstore-rust/pull/6))

## [0.3.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-trust-root-v0.2.0...sigstore-trust-root-v0.3.0) - 2025-11-28

### Other

- add staging trust root
- make all interfaces more type safe
- improve sign / verify flow, add conda specific test
- more cleanup of functions

## [0.2.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-trust-root-v0.1.1...sigstore-trust-root-v0.2.0) - 2025-11-27

### Other

- remove duplicated types, add license and readme files

## [0.1.1](https://github.com/wolfv/sigstore-rust/compare/sigstore-trust-root-v0.1.0...sigstore-trust-root-v0.1.1) - 2025-11-27

### Other

- fmt
