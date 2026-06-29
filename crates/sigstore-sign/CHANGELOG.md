# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-sign-v0.9.0...sigstore-sign-v0.10.0) - 2026-06-29

### Added

- *(trust-root)* [**breaking**] support trusting custom Sigstore instances over TUF ([#136](https://github.com/sigstore/sigstore-rust/pull/136))

## [0.9.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-sign-v0.8.0...sigstore-sign-v0.9.0) - 2026-06-17

### Other

- bump dependencies ([#127](https://github.com/sigstore/sigstore-rust/pull/127))
- Require complete SigningConfig from tuf ([#117](https://github.com/sigstore/sigstore-rust/pull/117))
- Don't advertize unreliable parsing mechanism ([#118](https://github.com/sigstore/sigstore-rust/pull/118))
- Support dsse as hashedrekord ([#99](https://github.com/sigstore/sigstore-rust/pull/99))
- Include OIDC in signing config, use TUF in examples ([#102](https://github.com/sigstore/sigstore-rust/pull/102))

## [0.8.0](https://github.com/sigstore/sigstore-rust/compare/sigstore-sign-v0.7.0...sigstore-sign-v0.8.0) - 2026-05-21

### Other

- Replace direct chrono usage with jiff ([#90](https://github.com/sigstore/sigstore-rust/pull/90))

## [0.6.5](https://github.com/sigstore/sigstore-rust/compare/sigstore-sign-v0.6.4...sigstore-sign-v0.6.5) - 2026-04-19

### Other

- API for fetching / using the trust root ([#69](https://github.com/sigstore/sigstore-rust/pull/69))
- Avoid hashing the payload twice

## [0.6.3](https://github.com/prefix-dev/sigstore-rust/compare/sigstore-sign-v0.6.2...sigstore-sign-v0.6.3) - 2026-02-06

### Added

- add custom templates and automatic browser open for better interactive flow ([#48](https://github.com/prefix-dev/sigstore-rust/pull/48))

### Other

- support --in-toto ([#59](https://github.com/prefix-dev/sigstore-rust/pull/59))

## [0.6.2](https://github.com/prefix-dev/sigstore-rust/compare/sigstore-sign-v0.6.1...sigstore-sign-v0.6.2) - 2026-02-04

### Other

- add native-tls feature, bump reqwest ([#51](https://github.com/prefix-dev/sigstore-rust/pull/51))

## [0.6.1](https://github.com/prefix-dev/sigstore-rust/compare/sigstore-sign-v0.6.0...sigstore-sign-v0.6.1) - 2026-01-26

### Added

- use `ambient-id` to detect tokens in CI pipelines ([#36](https://github.com/prefix-dev/sigstore-rust/pull/36))

## [0.6.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-sign-v0.5.0...sigstore-sign-v0.6.0) - 2025-12-08

### Other

- improve types and add interop test workflow ([#9](https://github.com/wolfv/sigstore-rust/pull/9))

## [0.5.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-sign-v0.4.0...sigstore-sign-v0.5.0) - 2025-12-01

### Added

- Add SigningConfig support and V2 bundle fixes ([#6](https://github.com/wolfv/sigstore-rust/pull/6))

## [0.4.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-sign-v0.3.0...sigstore-sign-v0.4.0) - 2025-11-28

### Other

- introduce new artifact api

## [0.3.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-sign-v0.2.0...sigstore-sign-v0.3.0) - 2025-11-28

### Other

- remove more types
- encode more certificates properly
- remove certifactePem
- unify certificate encoding
- simplifications by only supporting v03 bundle creation
- improve sign / verify flow, add conda specific test
- more cleanup of functions

## [0.2.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-sign-v0.1.1...sigstore-sign-v0.2.0) - 2025-11-27

### Other

- remove duplicated types, add license and readme files

## [0.1.1](https://github.com/wolfv/sigstore-rust/compare/sigstore-sign-v0.1.0...sigstore-sign-v0.1.1) - 2025-11-27

### Fixed

- fix publishing

### Other

- add new crates
