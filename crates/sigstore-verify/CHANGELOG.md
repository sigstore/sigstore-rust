# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-verify-v0.9.0...sigstore-verify-v0.10.0) - 2026-06-29

### Added

- *(trust-root)* [**breaking**] support trusting custom Sigstore instances over TUF ([#136](https://github.com/sigstore/sigstore-rust/pull/136))

## [0.9.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-verify-v0.8.0...sigstore-verify-v0.9.0) - 2026-06-17

### Other

- bump dependencies ([#127](https://github.com/sigstore/sigstore-rust/pull/127))
- separate structural validation from crypto verification ([#123](https://github.com/sigstore/sigstore-rust/pull/123))
- enforce valid_for in key accessors, surface parse errors ([#122](https://github.com/sigstore/sigstore-rust/pull/122))
- Add sigstore-tuf crate; bootstrap trusted roots over TUF without tough ([#106](https://github.com/sigstore/sigstore-rust/pull/106))
- harden message-signature verification, drop digest leak ([#119](https://github.com/sigstore/sigstore-rust/pull/119))
- Various improvements ([#109](https://github.com/sigstore/sigstore-rust/pull/109))
- simplify conformance client using native DSSE validation ([#111](https://github.com/sigstore/sigstore-rust/pull/111))
- Support dsse as hashedrekord ([#99](https://github.com/sigstore/sigstore-rust/pull/99))
- Refactor log entry consistency verification ([#103](https://github.com/sigstore/sigstore-rust/pull/103))
- Include OIDC in signing config, use TUF in examples ([#102](https://github.com/sigstore/sigstore-rust/pull/102))

## [0.8.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-verify-v0.7.0...sigstore-verify-v0.8.0) - 2026-05-21

### Other

- Replace direct chrono usage with jiff ([#90](https://github.com/sigstore/sigstore-rust/pull/90))

## [0.7.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-verify-v0.6.6...sigstore-verify-v0.7.0) - 2026-05-13

### Added

- support for GitHub's artifact attestation Sigstore instance ([#88](https://github.com/sigstore/sigstore-rust/pull/88))
- `VerificationPolicy::skip_sct()` builder method to skip Signed Certificate Timestamp verification (needed for trust domains whose certificates do not carry public Sigstore CT SCTs)

### Changed

- **BREAKING**: `VerificationPolicy` gained a new public field `verify_sct: bool` (defaults to `true`). Code that constructs `VerificationPolicy` via struct literal must add this field; users of `Default::default()` and the builder methods are unaffected.
- **BREAKING**: SCT verification is now controlled independently by `verify_sct` rather than implicitly gated on `verify_certificate`. `skip_certificate_chain()` continues to disable both.

## [0.6.5](https://github.com/sigstore/sigstore-rust/compare/sigstore-verify-v0.6.4...sigstore-verify-v0.6.5) - 2026-04-19

### Other

- API for fetching / using the trust root ([#69](https://github.com/sigstore/sigstore-rust/pull/69))

## [0.6.4](https://github.com/sigstore/sigstore-rust/compare/sigstore-verify-v0.6.3...sigstore-verify-v0.6.4) - 2026-03-06

### Fixed

- be more strict about unknown key types and verification ([#70](https://github.com/sigstore/sigstore-rust/pull/70))

## [0.6.2](https://github.com/prefix-dev/sigstore-rust/compare/sigstore-verify-v0.6.1...sigstore-verify-v0.6.2) - 2026-02-04

### Other

- add native-tls feature, bump reqwest ([#51](https://github.com/prefix-dev/sigstore-rust/pull/51))

## [0.6.1](https://github.com/prefix-dev/sigstore-rust/compare/sigstore-verify-v0.6.0...sigstore-verify-v0.6.1) - 2026-01-26

### Fixed

- *(conformance)* add verification with key ([#41](https://github.com/prefix-dev/sigstore-rust/pull/41))

## [0.6.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-verify-v0.5.0...sigstore-verify-v0.6.0) - 2025-12-08

### Added

- add fuzzing tests ([#13](https://github.com/wolfv/sigstore-rust/pull/13))

### Other

- improve types and add interop test workflow ([#9](https://github.com/wolfv/sigstore-rust/pull/9))

## [0.5.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-verify-v0.4.0...sigstore-verify-v0.5.0) - 2025-12-01

### Added

- Add SigningConfig support and V2 bundle fixes ([#6](https://github.com/wolfv/sigstore-rust/pull/6))

## [0.4.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-verify-v0.3.0...sigstore-verify-v0.4.0) - 2025-11-28

### Other

- introduce new artifact api

## [0.3.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-verify-v0.2.0...sigstore-verify-v0.3.0) - 2025-11-28

### Other

- make all interfaces more type safe
- remove more types
- improve sign / verify flow, add conda specific test
- more cleanup of functions
- remove manual verification code and use webpki

## [0.2.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-verify-v0.1.1...sigstore-verify-v0.2.0) - 2025-11-27

### Other

- require trust root in constructor, remove more unused code, update readme
- remove duplicated types, add license and readme files

## [0.1.1](https://github.com/wolfv/sigstore-rust/compare/sigstore-verify-v0.1.0...sigstore-verify-v0.1.1) - 2025-11-27

### Fixed

- fix verification
- fix publishing

### Other

- add conformance test
- add all test data
- add tests for verify
- add new crates
