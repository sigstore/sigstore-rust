"""Tests for the IdentityToken Python API."""
import os

import pytest

from sigstore import IdentityToken, IdentityTokenError


class TestIdentityTokenFromJwt:
    def test_from_jwt_email_token(self, jwt_with_email):
        token = IdentityToken.from_jwt(jwt_with_email)
        assert token.issuer == "https://accounts.google.com"
        assert token.subject == "108204268749914862134"
        assert token.identity == "user@example.com"

    def test_identity_prefers_email_over_subject(self, jwt_with_email):
        token = IdentityToken.from_jwt(jwt_with_email)
        assert token.identity == "user@example.com"
        assert token.identity != token.subject

    def test_identity_falls_back_to_subject(self, jwt_no_email):
        token = IdentityToken.from_jwt(jwt_no_email)
        assert token.identity == token.subject
        assert token.identity == "repo:org/repo/.github/workflows/release.yml@refs/heads/main"

    def test_issuer_is_str(self, jwt_with_email):
        token = IdentityToken.from_jwt(jwt_with_email)
        assert isinstance(token.issuer, str)
        assert len(token.issuer) > 0

    def test_subject_is_str(self, jwt_with_email):
        token = IdentityToken.from_jwt(jwt_with_email)
        assert isinstance(token.subject, str)
        assert len(token.subject) > 0

    def test_identity_is_str(self, jwt_with_email):
        token = IdentityToken.from_jwt(jwt_with_email)
        assert isinstance(token.identity, str)
        assert len(token.identity) > 0


class TestIdentityTokenExpiry:
    def test_is_expired_false_for_future_token(self, jwt_with_email):
        token = IdentityToken.from_jwt(jwt_with_email)
        assert token.is_expired is False

    def test_is_expired_true_for_past_token(self, jwt_expired):
        token = IdentityToken.from_jwt(jwt_expired)
        assert token.is_expired is True

    def test_is_expired_is_bool(self, jwt_with_email):
        token = IdentityToken.from_jwt(jwt_with_email)
        assert isinstance(token.is_expired, bool)


class TestIdentityTokenErrors:
    def test_from_jwt_not_jwt_raises(self):
        with pytest.raises(IdentityTokenError):
            IdentityToken.from_jwt("notajwt")

    def test_from_jwt_two_parts_raises(self):
        with pytest.raises(IdentityTokenError):
            IdentityToken.from_jwt("a.b")

    def test_from_jwt_bad_base64_raises(self):
        with pytest.raises(IdentityTokenError):
            IdentityToken.from_jwt("a.!!!.c")

    def test_from_jwt_missing_exp_raises(self):
        import base64, json
        # Valid header + payload without required 'exp' field
        header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"iss": "https://example.com", "sub": "user"}).encode()
        ).rstrip(b"=").decode()
        jwt = f"{header}.{payload}.sig"
        with pytest.raises(IdentityTokenError):
            IdentityToken.from_jwt(jwt)

    def test_from_jwt_empty_string_raises(self):
        with pytest.raises(IdentityTokenError):
            IdentityToken.from_jwt("")


class TestIdentityTokenRepr:
    def test_repr_starts_with_identity_token(self, jwt_with_email):
        token = IdentityToken.from_jwt(jwt_with_email)
        assert repr(token).startswith("IdentityToken(")

    def test_repr_contains_identity(self, jwt_with_email):
        token = IdentityToken.from_jwt(jwt_with_email)
        assert "user@example.com" in repr(token)

    def test_repr_contains_expired(self, jwt_with_email):
        token = IdentityToken.from_jwt(jwt_with_email)
        assert "expired=" in repr(token)


@pytest.mark.network
class TestIdentityTokenDetectAmbient:
    def test_detect_ambient_raises_outside_ci(self):
        """Outside of GitHub Actions, detect_ambient() should raise IdentityTokenError."""
        # If we're somehow in CI with OIDC available, this test doesn't apply —
        # skip it rather than fail.
        if os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"):
            pytest.skip("ambient OIDC is available in this environment")
        with pytest.raises(IdentityTokenError):
            IdentityToken.detect_ambient()
