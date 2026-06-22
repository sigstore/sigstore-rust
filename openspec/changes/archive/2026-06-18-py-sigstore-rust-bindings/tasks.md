# Tasks: py-sigstore-rust-bindings

## Phase 1 — Scaffolding

- [x] Add `"crates/sigstore-python"` to workspace members in root `Cargo.toml`
- [x] Create `crates/sigstore-python/Cargo.toml` with cdylib+rlib, pyo3 0.29 abi3-py310, pyo3-stub-gen, tokio, and all required sigstore workspace deps
- [x] Create `crates/sigstore-python/pyproject.toml` with maturin build backend, project name `py-sigstore-rust`, Python ≥3.10, mixed layout config pointing to `python/` source
- [x] Create `crates/sigstore-python/src/runtime.rs` — `OnceLock<tokio::runtime::Runtime>` with `get_runtime()` helper
- [x] Create `crates/sigstore-python/src/errors.rs` — PyO3 exception hierarchy (`SigstoreError`, `VerificationError`, `SigningError`, `BundleError`, `TrustedRootError`, `IdentityTokenError`) and `From` impls for each Rust error type
- [x] Create `crates/sigstore-python/src/lib.rs` — empty `#[pymodule]` that registers the module; imports all submodules; includes `define_stub_info_gatherer!(stub_info)`
- [x] Create `crates/sigstore-python/src/bin/stub_gen.rs` — calls `stub_info()` and `stub.generate()`
- [x] Create `crates/sigstore-python/python/py_sigstore_rust/__init__.py` — empty placeholder with `from py_sigstore_rust._internal import *`
- [ ] Verify `cargo check -p sigstore-python` passes with no errors

## Phase 2 — Core Sync Types

- [x] Create `crates/sigstore-python/src/bundle.rs` — `PyBundle` wrapping `sigstore_types::Bundle`; implements `from_json`, `to_json`, `media_type` property; annotated with `#[gen_stub_pyclass]` and `#[gen_stub_pymethods]`
- [x] Create `crates/sigstore-python/src/trust_root.rs` — `PyTrustedRoot` wrapping `sigstore_trust_root::TrustedRoot`; classmethods `production`, `staging`, `github`, `from_json`, `from_file`; async methods use `get_runtime().block_on()` + `py.allow_threads()`
- [x] Create `crates/sigstore-python/src/verify.rs` — `PyIdentity` wrapping `sigstore_verify::VerificationPolicy`; `PyVerifier` wrapping `sigstore_verify::Verifier`; `verify_artifact` and `verify_dsse` methods on `PyVerifier`; `PyVerifier::from_root` classmethod
- [x] Register `PyBundle`, `PyTrustedRoot`, `PyIdentity`, `PyVerifier` and all exception types in `src/lib.rs` module
- [x] Add module-level `verify()` free function in `src/lib.rs`
- [ ] Verify `cargo check -p sigstore-python` passes
- [ ] Run `cargo run --bin stub_gen` and confirm `_internal.pyi` is generated

## Phase 3 — Signing and OIDC

- [x] Create `crates/sigstore-python/src/oidc.rs` — `PyIdentityToken` wrapping `sigstore_oidc::IdentityToken`; classmethods `from_jwt`, `detect_ambient` (async→sync + GIL release); properties `issuer`, `subject`, `identity`, `is_expired`
- [x] Create `crates/sigstore-python/src/sign.rs` — `PySigner` wrapping `sigstore_sign::Signer`; classmethods `production`, `staging` (each take a `PyIdentityToken`); methods `sign_artifact`, `sign_dsse` (async→sync + GIL release)
- [x] Register `PyIdentityToken` and `PySigner` in `src/lib.rs`
- [x] Add module-level `sign()` free function in `src/lib.rs`
- [ ] Verify `cargo check -p sigstore-python` passes
- [ ] Run `cargo run --bin stub_gen` and confirm all new types appear in `_internal.pyi`

## Phase 4 — Python Facade and Stubs

- [x] Update `python/py_sigstore_rust/__init__.py` — explicit `__all__`, re-export all public classes and exceptions from `._internal`, add module docstring, add convenience `verify()` and `sign()` wrappers with full Python-level docstrings
- [x] Create `python/py_sigstore_rust/py.typed` — empty PEP 561 marker file
- [ ] Run `cargo run --bin stub_gen` to regenerate `_internal.pyi` with complete annotations
- [ ] Manually review `_internal.pyi` for any `Any` types that need override annotations; add `#[gen_stub(...)]` overrides in Rust source where needed
- [ ] Verify `maturin develop` builds and `import py_sigstore_rust` succeeds in Python
- [ ] Run `python -m mypy --strict python/py_sigstore_rust/` and fix any stub issues

## Phase 5 — CI and Release

- [x] Create `.github/workflows/wheels.yml` — matrix build for Linux x86_64+aarch64 (manylinux_2_28), macOS x86_64+aarch64, Windows x86_64; uses `PyO3/maturin-action@v1` with `working-directory: crates/sigstore-python`; Windows job uses `aws-lc-rs` `prebuilt-nasm` feature flag
- [x] Add `publish` job to `wheels.yml` that uploads to PyPI on git tag push using `MATURIN_PYPI_TOKEN` secret
- [x] Add `stub-check` job to CI that runs `cargo run --bin stub_gen` and fails if `_internal.pyi` is not up to date (using `git diff --exit-code`)
