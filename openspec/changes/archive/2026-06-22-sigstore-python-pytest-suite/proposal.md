# Proposal: sigstore-python-pytest-suite

## What

Add a pytest test suite to `crates/py-sigstore/` that exercises the Python API of the `sigstore` bindings crate.

The suite covers: `Bundle`, `Identity`, `TrustedRoot`, `Verifier`, `IdentityToken`, `Signer`, all exception types, and the module-level `verify()` / `sign()` convenience functions. Tests are organized by marker: unmarked tests run fully offline, `@pytest.mark.network` tests require live Sigstore infrastructure, and `@pytest.mark.ci` tests require a GitHub Actions OIDC environment.

## Why

The existing test coverage for the Python bindings is entirely at the Rust layer (`crates/sigstore-verify/tests/`). That gives confidence in cryptographic correctness but does not verify the Python-facing API:

- Do kwargs, default arguments, and optional parameters work as documented?
- Are exception types correct and catchable as `SigstoreError` subtypes?
- Do error messages contain useful information?
- Does `Bundle.from_json()` return a `str` (not `bytes`) from `to_json()`?
- Does the convenience `verify()` accept both a `Bundle` object and a JSON string?
- Does `IdentityToken.from_jwt()` correctly parse all properties including the `email`-over-`subject` fallback for `.identity`?

These are things only a Python-level test can catch. A pytest suite also gives contributors a fast feedback loop via `maturin develop && pytest` without needing to understand the Rust internals.

## Goals

- Full offline coverage of the Python API surface (parsing, construction, properties, repr, error paths)
- Cryptographic verification tests that run offline using the embedded production trusted root and real fixture bundles
- `@pytest.mark.network` tests for `TrustedRoot.production()`, `Verifier.production()`, etc.
- `@pytest.mark.ci` signing tests that auto-skip outside GitHub Actions
- Zero fixture duplication: reuse bundles from `crates/sigstore-verify/test_data/`
- pytest configured in `pyproject.toml`; no separate config files

## Non-Goals

- Testing internal Rust logic (that belongs in Rust `#[test]` blocks)
- Measuring cryptographic correctness (that is covered by `sigstore-verify` tests)
- Adding a test for every edge case already tested in Rust (trust the Rust layer)
- Fuzz testing or property-based testing in this change
- Setting up a local Sigstore instance for integration tests

## Approach

- `conftest.py` at the `crates/py-sigstore/` root computes fixture paths relative to `__file__`, resolving into `../../sigstore-verify/test_data/` and `../../sigstore-bundle/tests/fixtures/`
- `@pytest.mark.ci` auto-skips via a `pytest_runtest_setup` hook in `conftest.py` when `ACTIONS_ID_TOKEN_REQUEST_URL` is not set
- Fake JWTs for `IdentityToken` tests are constructed inline using `base64` + `json` — no real OIDC issuer needed
- `pyproject.toml` gains `[tool.pytest.ini_options]` and an `[project.optional-dependencies]` `test` group
