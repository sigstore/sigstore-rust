import base64
import json
import os
import pathlib

import pytest

# ---------------------------------------------------------------------------
# Workspace-relative fixture paths
# ---------------------------------------------------------------------------
_HERE = pathlib.Path(__file__).parent          # crates/sigstore-python/
_WORKSPACE = _HERE.parent.parent.parent        # repo root

VERIFY_BUNDLES = _WORKSPACE / "crates/sigstore-verify/test_data/bundles"
VERIFY_TRUSTED_ROOTS = _WORKSPACE / "crates/sigstore-verify/test_data/trusted_roots"
BUNDLE_FIXTURES = _WORKSPACE / "crates/sigstore-bundle/tests/fixtures"

# The embedded production trusted root — same source the Rust tests use.
# Prefer this over the test_data/trusted_roots/public-good.json fixture, which
# may be stale (e.g. missing the TSA certificate chain used by newer bundles).
EMBEDDED_PRODUCTION_ROOT = _WORKSPACE / "crates/sigstore-trust-root/src/trusted_root.json"

# ---------------------------------------------------------------------------
# Identity constants for real fixture bundles
# ---------------------------------------------------------------------------
# cosign-v3-blob.sigstore.json
COSIGN_IDENTITY = "w.vollprecht@gmail.com"
COSIGN_ISSUER = "https://github.com/login/oauth"

# conda-attestation.sigstore.json
CONDA_IDENTITY = (
    "https://github.com/prefix-dev/sigstore-example"
    "/.github/workflows/action.yaml@refs/heads/main"
)
CONDA_ISSUER = "https://token.actions.githubusercontent.com"


# ---------------------------------------------------------------------------
# Marker auto-skip: @pytest.mark.ci skips unless in GitHub Actions
# ---------------------------------------------------------------------------
def pytest_runtest_setup(item):
    if "ci" in item.keywords:
        if not os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"):
            pytest.skip("requires GitHub Actions OIDC (ACTIONS_ID_TOKEN_REQUEST_URL not set)")


# ---------------------------------------------------------------------------
# Bundle / artifact fixtures (session-scoped — read once per test run)
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
    # Use the embedded root from the trust-root crate — same as the Rust tests.
    # The test_data/trusted_roots/public-good.json fixture may be stale and lack
    # TSA certificates needed by newer bundles.
    return EMBEDDED_PRODUCTION_ROOT.read_text()


@pytest.fixture(scope="session")
def fixture_root_path():
    """Path string for the public-good.json fixture — used only by from_file() tests."""
    return str(VERIFY_TRUSTED_ROOTS / "public-good.json")


@pytest.fixture(scope="session")
def happy_path_bundle_json():
    return (BUNDLE_FIXTURES / "happy-path.json").read_text()


# ---------------------------------------------------------------------------
# Fake JWT factory — from_jwt() only decodes the payload, no sig verification
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
