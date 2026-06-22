# Design: sigstore-python-pytest-suite

## Directory Layout

```
crates/py-sigstore/
├── pyproject.toml               ← add [tool.pytest.ini_options] + test optional-deps
├── conftest.py                  ← fixture paths, marker registration, ci auto-skip
└── tests/
    ├── test_bundle.py
    ├── test_identity.py
    ├── test_trusted_root.py
    ├── test_verifier.py
    ├── test_exceptions.py
    ├── test_oidc.py
    └── test_signing.py
```

No fixture files are copied. All bundle and artifact fixtures are referenced by path from within `conftest.py`.

## pyproject.toml additions

```toml
[project.optional-dependencies]
test = ["pytest>=8.0"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "network: requires live network access to Sigstore infrastructure",
    "ci: requires GitHub Actions OIDC environment (ACTIONS_ID_TOKEN_REQUEST_URL)",
]
```

## conftest.py

```python
import base64
import json
import os
import pathlib

import pytest

# ---------------------------------------------------------------------------
# Workspace-relative fixture paths
# ---------------------------------------------------------------------------
_HERE = pathlib.Path(__file__).parent          # crates/py-sigstore/
_WORKSPACE = _HERE.parent.parent               # repo root

VERIFY_BUNDLES = _WORKSPACE / "crates/sigstore-verify/test_data/bundles"
VERIFY_TRUSTED_ROOTS = _WORKSPACE / "crates/sigstore-verify/test_data/trusted_roots"
BUNDLE_FIXTURES = _WORKSPACE / "crates/sigstore-bundle/tests/fixtures"

# ---------------------------------------------------------------------------
# Marker auto-skip: @pytest.mark.ci skips unless in GitHub Actions
# ---------------------------------------------------------------------------
def pytest_runtest_setup(item):
    if "ci" in item.keywords:
        if not os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"):
            pytest.skip("requires GitHub Actions OIDC (ACTIONS_ID_TOKEN_REQUEST_URL not set)")

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def cosign_bundle_json():
    return (VERIFY_BUNDLES / "cosign-v3-blob.sigstore.json").read_text()

@pytest.fixture(scope="session")
def cosign_artifact():
    return (VERIFY_BUNDLES / "cosign-v3-blob.txt").read_bytes()

@pytest.fixture(scope="session")
def conda_bundle_json():
    return (VERIFY_BUNDLES / "conda-attestation.sigstore.json").read_text()

@pytest.fixture(scope="session")
def conda_artifact():
    return (VERIFY_BUNDLES / "signed-package-2.1.0-hb0f4dca_0.conda").read_bytes()

@pytest.fixture(scope="session")
def dsse_bundle_json():
    return (VERIFY_BUNDLES / "dsse.sigstore.json").read_text()

@pytest.fixture(scope="session")
def dsse_2sigs_bundle_json():
    return (VERIFY_BUNDLES / "dsse-2sigs.sigstore.json").read_text()

@pytest.fixture(scope="session")
def bundle_no_log_entry_json():
    return (VERIFY_BUNDLES / "bundle_no_log_entry.txt.sigstore").read_text()

@pytest.fixture(scope="session")
def bundle_no_cert_json():
    return (VERIFY_BUNDLES / "bundle_no_cert_v1.txt.sigstore").read_text()

@pytest.fixture(scope="session")
def production_root_json():
    return (VERIFY_TRUSTED_ROOTS / "public-good.json").read_text()

@pytest.fixture(scope="session")
def happy_path_bundle_json():
    return (BUNDLE_FIXTURES / "happy-path.json").read_text()

# ---------------------------------------------------------------------------
# Fake JWT factory — no signature verification in from_jwt()
# ---------------------------------------------------------------------------
def make_jwt(claims: dict) -> str:
    """Build a syntactically valid JWT with arbitrary claims. Signature is fake."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesig"

@pytest.fixture
def jwt_with_email():
    return make_jwt({
        "iss": "https://accounts.google.com",
        "sub": "108204268749914862134",
        "email": "user@example.com",
        "exp": 9_999_999_999,
        "iat": 1_700_000_000,
    })

@pytest.fixture
def jwt_no_email():
    return make_jwt({
        "iss": "https://token.actions.githubusercontent.com",
        "sub": "repo:org/repo/.github/workflows/release.yml@refs/heads/main",
        "exp": 9_999_999_999,
        "iat": 1_700_000_000,
    })

@pytest.fixture
def jwt_expired():
    return make_jwt({
        "iss": "https://accounts.google.com",
        "sub": "user123",
        "email": "user@example.com",
        "exp": 1,   # 1970-01-01T00:00:01Z — always expired
        "iat": 0,
    })
```

## Test modules

### test_bundle.py

| Test | What it checks |
|---|---|
| `test_from_json_cosign_v03` | parses `cosign-v3-blob.sigstore.json`; `media_type` contains `v0.3` |
| `test_from_json_dsse_v01` | parses `dsse.sigstore.json`; `media_type` contains `0.1` |
| `test_from_json_happy_path` | parses `happy-path.json` |
| `test_to_json_roundtrip` | `Bundle.from_json(b.to_json()).media_type == b.media_type` |
| `test_media_type_is_str` | `isinstance(bundle.media_type, str)` |
| `test_from_json_invalid_raises` | `Bundle.from_json("not json")` → `BundleError` |
| `test_from_json_empty_raises` | `Bundle.from_json("")` → `BundleError` |
| `test_from_json_wrong_type_raises` | `Bundle.from_json(123)` → `TypeError` |
| `test_repr` | `repr(bundle)` starts with `"Bundle("` |

### test_identity.py

| Test | What it checks |
|---|---|
| `test_identity_only` | `Identity("user@example.com").identity == "user@example.com"` |
| `test_identity_issuer_none` | `.issuer is None` when not provided |
| `test_identity_with_issuer` | both `.identity` and `.issuer` set correctly |
| `test_identity_github_uri` | long GitHub Actions URI round-trips correctly |
| `test_identity_is_str_or_none` | property types are `str | None` |
| `test_repr` | `repr(Identity(...))` starts with `"Identity("` |

### test_trusted_root.py

| Test | What it checks |
|---|---|
| `test_github_offline` | `TrustedRoot.github()` succeeds with no network |
| `test_from_json_valid` | parses `public-good.json` content |
| `test_from_json_garbage_raises` | `TrustedRoot.from_json("{}")` → `TrustedRootError` |
| `test_from_file_valid` | `TrustedRoot.from_file(path_to_public_good_json)` succeeds |
| `test_from_file_missing_raises` | `TrustedRoot.from_file("/nonexistent")` → `TrustedRootError` |
| `test_repr` | `repr(root)` starts with `"TrustedRoot("` |
| `test_production` *(network)* | `TrustedRoot.production()` succeeds |
| `test_staging` *(network)* | `TrustedRoot.staging()` succeeds |

### test_verifier.py

| Test | What it checks |
|---|---|
| `test_github_offline` | `Verifier.github()` succeeds with no network |
| `test_from_root` | `Verifier.from_root(TrustedRoot.github())` succeeds |
| `test_verify_artifact_cosign` | verifies cosign blob against production root; returns `None` |
| `test_verify_artifact_wrong_bytes` | wrong artifact → `VerificationError` |
| `test_verify_artifact_wrong_identity` | wrong identity string → `VerificationError` |
| `test_verify_artifact_error_msg_nonempty` | `VerificationError` message is non-empty string |
| `test_verify_dsse_conda` | verifies conda package against DSSE bundle; returns `(str, bytes)` |
| `test_verify_dsse_payload_type` | returned `payload_type` is `"application/vnd.in-toto+json"` |
| `test_verify_dsse_wrong_artifact` | wrong artifact bytes → `VerificationError` |
| `test_verify_dsse_on_message_sig_bundle` | `verify_dsse()` on cosign bundle → `VerificationError` |
| `test_convenience_verify_with_bundle_obj` | `verify(bytes, bundle_obj, identity=...)` → `None` |
| `test_convenience_verify_with_json_str` | `verify(bytes, json_str, identity=...)` → `None` |
| `test_convenience_verify_wrong_bundle_type` | `verify(bytes, 42, ...)` → `TypeError` |
| `test_production` *(network)* | `Verifier.production()` returns a `Verifier` |
| `test_staging` *(network)* | `Verifier.staging()` returns a `Verifier` |

### test_exceptions.py

| Test | What it checks |
|---|---|
| `test_all_subclass_sigstore_error` | each specific exception is a subclass of `SigstoreError` |
| `test_sigstore_error_subclass_exception` | `SigstoreError` is subclass of `Exception` |
| `test_catch_as_base` | `except SigstoreError` catches `VerificationError`, `BundleError`, etc. |
| `test_bundle_error_has_message` | `BundleError` raised from bad JSON has non-empty message |
| `test_verification_error_has_message` | `VerificationError` from wrong identity has non-empty message |
| `test_trusted_root_error_has_message` | `TrustedRootError` from bad JSON has non-empty message |
| `test_identity_token_error_has_message` | `IdentityTokenError` from bad JWT has non-empty message |

### test_oidc.py

| Test | What it checks |
|---|---|
| `test_from_jwt_email_token` | parses `jwt_with_email`; `.issuer`, `.subject`, `.identity` correct |
| `test_identity_prefers_email` | `.identity` returns email when present |
| `test_identity_falls_back_to_sub` | `.identity` returns subject when no email claim |
| `test_is_expired_false` | far-future `exp` → `.is_expired == False` |
| `test_is_expired_true` | `exp=1` → `.is_expired == True` |
| `test_issuer_is_str` | `isinstance(token.issuer, str)` |
| `test_subject_is_str` | `isinstance(token.subject, str)` |
| `test_identity_is_str` | `isinstance(token.identity, str)` |
| `test_from_jwt_not_jwt_raises` | `from_jwt("notajwt")` → `IdentityTokenError` |
| `test_from_jwt_two_parts_raises` | `from_jwt("a.b")` → `IdentityTokenError` |
| `test_from_jwt_bad_b64_raises` | `from_jwt("a.!!!.c")` → `IdentityTokenError` |
| `test_from_jwt_missing_exp_raises` | JWT payload without `exp` → `IdentityTokenError` |
| `test_repr` | `repr(token)` starts with `"IdentityToken("` |
| `test_detect_ambient_no_env` *(network)* | raises `IdentityTokenError` when env vars absent |

### test_signing.py

| Test | What it checks |
|---|---|
| `test_signer_production_expired_token` | `Signer.production(expired_token)` → `IdentityTokenError` |
| `test_signer_staging_expired_token` | `Signer.staging(expired_token)` → `IdentityTokenError` |
| `test_sign_convenience_expired_token` | `sign(b"data", expired_token)` → `IdentityTokenError` |
| `test_sign_convenience_wrong_token_type` | `sign(b"data", token=42)` → `TypeError` |
| `test_sign_artifact` *(ci)* | signs bytes with ambient token → returns `Bundle` |
| `test_sign_dsse` *(ci)* | signs in-toto statement → returns `Bundle` with DSSE envelope |
| `test_sign_then_verify` *(ci)* | sign → verify roundtrip succeeds |

## Fixture paths summary

```
_WORKSPACE/
  crates/sigstore-verify/test_data/
    bundles/
      cosign-v3-blob.sigstore.json      → MessageSignature v0.3
      cosign-v3-blob.txt                → artifact: "test content for cosign\n"
      conda-attestation.sigstore.json   → DSSE v0.3 (identity: prefix-dev/sigstore-example)
      signed-package-2.1.0-hb0f4dca_0.conda  → artifact for conda attestation
      dsse.sigstore.json                → DSSE v0.1
      dsse-2sigs.sigstore.json          → error case
      bundle_no_log_entry.txt.sigstore  → error case
      bundle_no_cert_v1.txt.sigstore    → error case
    trusted_roots/
      public-good.json                  → for TrustedRoot.from_file() test
  crates/sigstore-bundle/tests/fixtures/
    happy-path.json                     → v0.3 DSSE bundle
```

## Verification identity constants

These are the identity/issuer values expected by the real fixture bundles:

```python
# cosign-v3-blob.sigstore.json
COSIGN_IDENTITY = "w.vollprecht@gmail.com"
COSIGN_ISSUER = "https://github.com/login/oauth"

# conda-attestation.sigstore.json
CONDA_IDENTITY = (
    "https://github.com/prefix-dev/sigstore-example"
    "/.github/workflows/action.yaml@refs/heads/main"
)
CONDA_ISSUER = "https://token.actions.githubusercontent.com"
```

These are defined as module-level constants in `conftest.py` so every test module can import them cleanly.

## Running the tests

```bash
# Build the extension first
cd crates/py-sigstore
maturin develop

# Run all offline tests (default)
pytest

# Run offline tests only (explicit)
pytest -m "not network and not ci"

# Include network tests
pytest -m "not ci"

# Run everything (in CI with OIDC available)
pytest
```

## pyproject.toml diff

```toml
# Add to existing pyproject.toml:

[project.optional-dependencies]
test = ["pytest>=8.0"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "network: requires live network access to Sigstore infrastructure",
    "ci: requires GitHub Actions OIDC environment (ACTIONS_ID_TOKEN_REQUEST_URL)",
]
```
