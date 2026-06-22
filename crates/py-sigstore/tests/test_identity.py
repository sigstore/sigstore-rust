"""Tests for the Identity (verification policy) Python API."""
from sigstore import Identity

GITHUB_WORKFLOW_URI = (
    "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main"
)


class TestIdentityConstruction:
    def test_identity_only(self):
        policy = Identity("user@example.com")
        assert policy.identity == "user@example.com"

    def test_identity_issuer_none_by_default(self):
        policy = Identity("user@example.com")
        assert policy.issuer is None

    def test_identity_with_issuer(self):
        policy = Identity("user@example.com", issuer="https://accounts.google.com")
        assert policy.identity == "user@example.com"
        assert policy.issuer == "https://accounts.google.com"

    def test_identity_issuer_as_kwarg(self):
        policy = Identity("user@example.com", issuer="https://accounts.google.com")
        assert policy.issuer == "https://accounts.google.com"

    def test_identity_github_uri(self):
        policy = Identity(GITHUB_WORKFLOW_URI)
        assert policy.identity == GITHUB_WORKFLOW_URI

    def test_identity_github_uri_with_issuer(self):
        policy = Identity(
            GITHUB_WORKFLOW_URI,
            issuer="https://token.actions.githubusercontent.com",
        )
        assert policy.identity == GITHUB_WORKFLOW_URI
        assert policy.issuer == "https://token.actions.githubusercontent.com"


class TestIdentityTypes:
    def test_identity_is_str(self):
        policy = Identity("user@example.com")
        assert isinstance(policy.identity, str)

    def test_issuer_is_none_type(self):
        policy = Identity("user@example.com")
        assert policy.issuer is None

    def test_issuer_is_str_when_set(self):
        policy = Identity("user@example.com", issuer="https://accounts.google.com")
        assert isinstance(policy.issuer, str)


class TestIdentityRepr:
    def test_repr_starts_with_identity(self):
        policy = Identity("user@example.com")
        assert repr(policy).startswith("Identity(")

    def test_repr_with_issuer(self):
        policy = Identity("user@example.com", issuer="https://accounts.google.com")
        r = repr(policy)
        assert repr(policy).startswith("Identity(")
        assert "user@example.com" in r
        assert "accounts.google.com" in r
