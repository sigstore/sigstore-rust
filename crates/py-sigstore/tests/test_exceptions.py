"""Tests for the exception hierarchy Python API."""
import pytest

from sigstore import (
    Bundle,
    Identity,
    IdentityToken,
    TrustedRoot,
    Verifier,
    SigstoreError,
    VerificationError,
    SigningError,
    BundleError,
    TrustedRootError,
    IdentityTokenError,
)


_ALL_SPECIFIC_EXCEPTIONS = [
    VerificationError,
    SigningError,
    BundleError,
    TrustedRootError,
    IdentityTokenError,
]


class TestExceptionHierarchy:
    @pytest.mark.parametrize("exc_class", _ALL_SPECIFIC_EXCEPTIONS)
    def test_all_subclass_sigstore_error(self, exc_class):
        assert issubclass(exc_class, SigstoreError)

    def test_sigstore_error_subclass_of_exception(self):
        assert issubclass(SigstoreError, Exception)

    @pytest.mark.parametrize("exc_class", _ALL_SPECIFIC_EXCEPTIONS)
    def test_all_subclass_exception(self, exc_class):
        assert issubclass(exc_class, Exception)

    @pytest.mark.parametrize("exc_class", _ALL_SPECIFIC_EXCEPTIONS)
    def test_not_subclass_of_each_other(self, exc_class):
        others = [e for e in _ALL_SPECIFIC_EXCEPTIONS if e is not exc_class]
        for other in others:
            assert not issubclass(exc_class, other), (
                f"{exc_class.__name__} should not be a subclass of {other.__name__}"
            )


class TestCatchAsBase:
    def test_catch_verification_error_as_sigstore_error(
        self, production_root_json, cosign_bundle_json, cosign_artifact
    ):
        root = TrustedRoot.from_json(production_root_json)
        verifier = Verifier.from_root(root)
        bundle = Bundle.from_json(cosign_bundle_json)
        policy = Identity("completely-wrong@example.com")
        caught = False
        try:
            verifier.verify_artifact(cosign_artifact, bundle, policy)
        except SigstoreError:
            caught = True
        assert caught

    def test_catch_bundle_error_as_sigstore_error(self):
        caught = False
        try:
            Bundle.from_json("not json")
        except SigstoreError:
            caught = True
        assert caught

    def test_catch_trusted_root_error_as_sigstore_error(self):
        caught = False
        try:
            TrustedRoot.from_json("{}")
        except SigstoreError:
            caught = True
        assert caught

    def test_catch_identity_token_error_as_sigstore_error(self):
        caught = False
        try:
            IdentityToken.from_jwt("notajwt")
        except SigstoreError:
            caught = True
        assert caught


class TestExceptionMessages:
    def test_bundle_error_has_message(self):
        with pytest.raises(BundleError) as exc_info:
            Bundle.from_json("not json")
        assert str(exc_info.value) != ""

    def test_trusted_root_error_has_message(self):
        with pytest.raises(TrustedRootError) as exc_info:
            TrustedRoot.from_json("{}")
        assert str(exc_info.value) != ""

    def test_identity_token_error_has_message(self):
        with pytest.raises(IdentityTokenError) as exc_info:
            IdentityToken.from_jwt("notajwt")
        assert str(exc_info.value) != ""

    def test_verification_error_has_message(
        self, production_root_json, cosign_bundle_json, cosign_artifact
    ):
        root = TrustedRoot.from_json(production_root_json)
        verifier = Verifier.from_root(root)
        bundle = Bundle.from_json(cosign_bundle_json)
        policy = Identity("completely-wrong@example.com")
        with pytest.raises(VerificationError) as exc_info:
            verifier.verify_artifact(cosign_artifact, bundle, policy)
        assert str(exc_info.value) != ""

    def test_trusted_root_error_file_missing_has_message(self):
        with pytest.raises(TrustedRootError) as exc_info:
            TrustedRoot.from_file("/nonexistent/path.json")
        assert str(exc_info.value) != ""
