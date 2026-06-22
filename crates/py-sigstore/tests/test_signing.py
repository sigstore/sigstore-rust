"""Tests for the Signer Python API and sign() convenience function."""
import json

import pytest

from sigstore import (
    Bundle,
    Identity,
    IdentityToken,
    Signer,
    Verifier,
    IdentityTokenError,
    sign,
)


class TestSignerErrorPaths:
    """Offline tests — only exercise error paths that don't require a real OIDC token."""

    def test_signer_production_expired_token_raises(self, jwt_expired):
        token = IdentityToken.from_jwt(jwt_expired)
        with pytest.raises(IdentityTokenError):
            Signer.production(token)

    def test_signer_staging_expired_token_raises(self, jwt_expired):
        token = IdentityToken.from_jwt(jwt_expired)
        with pytest.raises(IdentityTokenError):
            Signer.staging(token)

    def test_sign_convenience_expired_token_raises(self, jwt_expired):
        token = IdentityToken.from_jwt(jwt_expired)
        with pytest.raises(IdentityTokenError):
            sign(b"artifact bytes", token)

    def test_sign_convenience_wrong_token_type_raises(self):
        with pytest.raises(TypeError):
            sign(b"artifact bytes", token=42)  # type: ignore[arg-type]

    def test_sign_expired_jwt_string_raises(self, jwt_expired):
        """sign() also accepts a raw JWT string — expired token must raise."""
        with pytest.raises(IdentityTokenError):
            sign(b"artifact bytes", jwt_expired)


@pytest.mark.ci
class TestSignerCi:
    """Signing tests that require a live GitHub Actions OIDC token.
    These are auto-skipped outside of GitHub Actions via conftest.pytest_runtest_setup.
    """

    @pytest.fixture(scope="class")
    def ambient_token(self):
        return IdentityToken.detect_ambient()

    def test_sign_artifact_returns_bundle(self, ambient_token):
        signer = Signer.production(ambient_token)
        bundle = signer.sign_artifact(b"test artifact content")
        assert isinstance(bundle, Bundle)

    def test_sign_artifact_bundle_has_media_type(self, ambient_token):
        signer = Signer.production(ambient_token)
        bundle = signer.sign_artifact(b"test artifact content")
        assert isinstance(bundle.media_type, str)
        assert "sigstore" in bundle.media_type

    def test_sign_artifact_bundle_roundtrips(self, ambient_token):
        signer = Signer.production(ambient_token)
        bundle = signer.sign_artifact(b"roundtrip test")
        restored = Bundle.from_json(bundle.to_json())
        assert restored.media_type == bundle.media_type

    def test_sign_dsse_returns_bundle(self, ambient_token):
        statement = json.dumps({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "artifact.txt", "digest": {"sha256": "a" * 64}}],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {},
        }).encode()
        signer = Signer.production(ambient_token)
        bundle = signer.sign_dsse(statement, "application/vnd.in-toto+json")
        assert isinstance(bundle, Bundle)

    def test_sign_then_verify_roundtrip(self, ambient_token):
        artifact = b"artifact to sign and verify"
        signer = Signer.production(ambient_token)
        bundle = signer.sign_artifact(artifact)

        # Verify using production infrastructure (also requires network, but we're in CI)
        verifier = Verifier.production()
        # Identity matches the ambient token's identity
        policy = Identity(ambient_token.identity, issuer=ambient_token.issuer)
        result = verifier.verify_artifact(artifact, bundle, policy)
        assert result is None  # success

    def test_sign_convenience_with_ambient_token(self, ambient_token):
        bundle = sign(b"convenience sign test", ambient_token)
        assert isinstance(bundle, Bundle)

    def test_sign_convenience_no_token_uses_ambient(self):
        """sign() with no token auto-detects ambient credential."""
        bundle = sign(b"ambient sign test")
        assert isinstance(bundle, Bundle)
