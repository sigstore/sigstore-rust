# Tasks: sigstore-python-pytest-suite

## Phase 1 — Infrastructure

- [x] Add `[project.optional-dependencies] test = ["pytest>=8.0"]` to `crates/py-sigstore/pyproject.toml`
- [x] Add `[tool.pytest.ini_options]` with `testpaths = ["tests"]` and `markers` declarations to `pyproject.toml`
- [x] Create `crates/py-sigstore/conftest.py` with:
  - Workspace-relative fixture path constants (`VERIFY_BUNDLES`, `VERIFY_TRUSTED_ROOTS`, `BUNDLE_FIXTURES`)
  - `pytest_runtest_setup` hook that auto-skips `@pytest.mark.ci` tests when `ACTIONS_ID_TOKEN_REQUEST_URL` is not set
  - Session-scoped fixtures for all bundle/artifact file contents (`cosign_bundle_json`, `cosign_artifact`, `conda_bundle_json`, `conda_artifact`, `dsse_bundle_json`, `dsse_2sigs_bundle_json`, `bundle_no_log_entry_json`, `bundle_no_cert_json`, `production_root_json`, `happy_path_bundle_json`)
  - `make_jwt(claims)` helper and function-scoped fixtures `jwt_with_email`, `jwt_no_email`, `jwt_expired`
  - Module-level identity constants `COSIGN_ISSUER`, `CONDA_IDENTITY`, `CONDA_ISSUER`
- [x] Create `crates/py-sigstore/tests/` directory
- [x] Verify `maturin develop` succeeds and `import sigstore` works in a Python shell

## Phase 2 — Bundle tests

- [x] Create `crates/py-sigstore/tests/test_bundle.py` with:
  - `test_from_json_cosign_v03`: parse cosign bundle, assert `media_type` contains `"v0.3"`
  - `test_from_json_dsse_v01`: parse dsse v0.1 bundle, assert `media_type` contains `"0.1"`
  - `test_from_json_happy_path`: parse happy-path bundle without error
  - `test_to_json_roundtrip`: `Bundle.from_json(b.to_json()).media_type == b.media_type`
  - `test_media_type_is_str`: `isinstance(bundle.media_type, str)`
  - `test_from_json_invalid_raises`: `Bundle.from_json("not json")` raises `BundleError`
  - `test_from_json_empty_raises`: `Bundle.from_json("")` raises `BundleError`
  - `test_from_json_wrong_type_raises`: `Bundle.from_json(123)` raises `TypeError`
  - `test_repr`: `repr(bundle)` starts with `"Bundle("`

## Phase 3 — Identity tests

- [x] Create `crates/py-sigstore/tests/test_identity.py` with:
  - `test_identity_only`: `.identity` set, `.issuer` is `None`
  - `test_identity_issuer_none`: explicit check that default issuer is `None`
  - `test_identity_with_issuer`: both `.identity` and `.issuer` set correctly
  - `test_identity_github_uri`: long GitHub Actions workflow URI round-trips correctly
  - `test_identity_is_str_or_none`: assert types of `.identity` and `.issuer`
  - `test_repr`: `repr(Identity(...))` starts with `"Identity("`

## Phase 4 — TrustedRoot tests

- [x] Create `crates/py-sigstore/tests/test_trusted_root.py` with:
  - `test_github_offline`: `TrustedRoot.github()` succeeds without network
  - `test_from_json_valid`: `TrustedRoot.from_json(production_root_json)` succeeds
  - `test_from_json_garbage_raises`: `TrustedRoot.from_json("{}")` raises `TrustedRootError`
  - `test_from_file_valid`: `TrustedRoot.from_file(str(path))` loads `public-good.json`
  - `test_from_file_missing_raises`: `TrustedRoot.from_file("/nonexistent/path.json")` raises `TrustedRootError`
  - `test_repr`: `repr(root)` starts with `"TrustedRoot("`
  - `test_production` *(network)*: `TrustedRoot.production()` returns a `TrustedRoot`
  - `test_staging` *(network)*: `TrustedRoot.staging()` returns a `TrustedRoot`

## Phase 5 — Verifier tests

- [x] Create `crates/py-sigstore/tests/test_verifier.py` with:
  - `test_github_offline`: `Verifier.github()` succeeds without network
  - `test_from_root`: `Verifier.from_root(TrustedRoot.github())` succeeds
  - `test_verify_artifact_cosign`: verify cosign blob with `production_root_json`; `verify_artifact` returns `None`
  - `test_verify_artifact_wrong_bytes`: tampered artifact bytes raise `VerificationError`
  - `test_verify_artifact_wrong_identity`: wrong identity string raises `VerificationError`
  - `test_verify_artifact_error_msg_nonempty`: `VerificationError` message is a non-empty string
  - `test_verify_dsse_conda`: verify conda package with DSSE bundle; returns `(str, bytes)` tuple
  - `test_verify_dsse_payload_type`: returned payload type is `"application/vnd.in-toto+json"`
  - `test_verify_dsse_wrong_artifact`: wrong artifact bytes raise `VerificationError`
  - `test_verify_dsse_on_message_sig_bundle`: calling `verify_dsse()` on a MessageSignature bundle raises `VerificationError`
  - `test_convenience_verify_with_bundle_obj`: `verify(bytes, bundle_obj, identity=..., issuer=..., trusted_root=root)` returns `None`
  - `test_convenience_verify_with_json_str`: `verify(bytes, json_str, identity=..., issuer=..., trusted_root=root)` returns `None`
  - `test_convenience_verify_wrong_bundle_type`: `verify(bytes, 42, identity=...)` raises `TypeError`
  - `test_production` *(network)*: `Verifier.production()` returns a `Verifier`
  - `test_staging` *(network)*: `Verifier.staging()` returns a `Verifier`

## Phase 6 — Exception tests

- [x] Create `crates/py-sigstore/tests/test_exceptions.py` with:
  - `test_all_subclass_sigstore_error`: parametrized over all 5 specific exceptions; each is a subclass of `SigstoreError`
  - `test_sigstore_error_subclass_exception`: `issubclass(SigstoreError, Exception)`
  - `test_catch_as_base_verification`: `except SigstoreError` catches a live `VerificationError`
  - `test_catch_as_base_bundle`: `except SigstoreError` catches a live `BundleError`
  - `test_bundle_error_has_message`: `BundleError` from bad JSON has non-empty `str(e)`
  - `test_verification_error_has_message`: `VerificationError` from wrong identity has non-empty message
  - `test_trusted_root_error_has_message`: `TrustedRootError` from bad JSON has non-empty message
  - `test_identity_token_error_has_message`: `IdentityTokenError` from malformed JWT has non-empty message

## Phase 7 — OIDC / IdentityToken tests

- [x] Create `crates/py-sigstore/tests/test_oidc.py` with:
  - `test_from_jwt_email_token`: `.issuer`, `.subject`, `.identity` match claims
  - `test_identity_prefers_email`: `.identity` returns email when `email` claim is present
  - `test_identity_falls_back_to_sub`: `.identity` returns `sub` when no `email` claim
  - `test_is_expired_false`: far-future `exp` → `.is_expired is False`
  - `test_is_expired_true`: `exp=1` → `.is_expired is True`
  - `test_issuer_is_str`: `isinstance(token.issuer, str)`
  - `test_subject_is_str`: `isinstance(token.subject, str)`
  - `test_identity_is_str`: `isinstance(token.identity, str)`
  - `test_from_jwt_not_jwt_raises`: `IdentityToken.from_jwt("notajwt")` raises `IdentityTokenError`
  - `test_from_jwt_two_parts_raises`: `IdentityToken.from_jwt("a.b")` raises `IdentityTokenError`
  - `test_from_jwt_bad_b64_raises`: `IdentityToken.from_jwt("a.!!!.c")` raises `IdentityTokenError`
  - `test_from_jwt_missing_exp_raises`: JWT payload without `exp` field raises `IdentityTokenError`
  - `test_repr`: `repr(token)` starts with `"IdentityToken("`
  - `test_detect_ambient_no_env` *(network)*: raises `IdentityTokenError` when OIDC env vars are absent

## Phase 8 — Signing tests

- [x] Create `crates/py-sigstore/tests/test_signing.py` with:
  - `test_signer_production_expired_token`: `Signer.production(expired_token)` raises `IdentityTokenError`
  - `test_signer_staging_expired_token`: `Signer.staging(expired_token)` raises `IdentityTokenError`
  - `test_sign_convenience_expired_token`: `sign(b"data", expired_token)` raises `IdentityTokenError`
  - `test_sign_convenience_wrong_token_type`: `sign(b"data", token=42)` raises `TypeError`
  - `test_sign_artifact` *(ci)*: sign artifact bytes with ambient OIDC token → returns `Bundle`
  - `test_sign_dsse` *(ci)*: sign in-toto DSSE statement → returns `Bundle`
  - `test_sign_then_verify` *(ci)*: full roundtrip — sign artifact, then `Verifier.production().verify_artifact()` succeeds

## Phase 9 — Verification and CI integration

- [x] Run `pytest -m "not network and not ci"` locally and confirm all offline tests pass
- [x] Add a `test` job to `.github/workflows/wheels.yml` that:
  - Runs after the `linux` build job
  - Installs the built wheel + pytest
  - Executes `pytest -m "not ci"` (offline + network tests, no signing)
- [ ] Verify CI passes on a pull request