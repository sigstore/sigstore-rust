"""Tests for the Verifier Python API."""
import pytest

from sigstore import (
    Bundle,
    Identity,
    TrustedRoot,
    Verifier,
    VerificationError,
    verify,
)

from conftest import COSIGN_IDENTITY, COSIGN_ISSUER, CONDA_IDENTITY, CONDA_ISSUER


# ---------------------------------------------------------------------------
# Helpers — build a pre-loaded production TrustedRoot from the fixture file
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def production_root(production_root_json):
    return TrustedRoot.from_json(production_root_json)


@pytest.fixture(scope="module")
def cosign_bundle(cosign_bundle_json):
    return Bundle.from_json(cosign_bundle_json)


@pytest.fixture(scope="module")
def conda_bundle(conda_bundle_json):
    return Bundle.from_json(conda_bundle_json)


class TestVerifierConstruction:
    def test_github_offline(self):
        """Verifier.github() uses an embedded root — no network required."""
        verifier = Verifier.github()
        assert verifier is not None

    def test_from_root_github(self):
        root = TrustedRoot.github()
        verifier = Verifier.from_root(root)
        assert verifier is not None

    def test_from_root_production(self, production_root):
        verifier = Verifier.from_root(production_root)
        assert verifier is not None


class TestVerifyArtifact:
    def test_verify_artifact_cosign_succeeds(
        self, cosign_artifact, cosign_bundle, production_root
    ):
        verifier = Verifier.from_root(production_root)
        policy = Identity(COSIGN_IDENTITY, issuer=COSIGN_ISSUER)
        result = verifier.verify_artifact(cosign_artifact, cosign_bundle, policy)
        assert result is None  # success returns None

    def test_verify_artifact_wrong_bytes_raises(
        self, cosign_bundle, production_root
    ):
        verifier = Verifier.from_root(production_root)
        policy = Identity(COSIGN_IDENTITY, issuer=COSIGN_ISSUER)
        with pytest.raises(VerificationError):
            verifier.verify_artifact(b"this is not the signed content", cosign_bundle, policy)

    def test_verify_artifact_wrong_identity_raises(
        self, cosign_artifact, cosign_bundle, production_root
    ):
        verifier = Verifier.from_root(production_root)
        policy = Identity("wrong-user@example.com", issuer=COSIGN_ISSUER)
        with pytest.raises(VerificationError):
            verifier.verify_artifact(cosign_artifact, cosign_bundle, policy)

    def test_verify_artifact_error_message_nonempty(
        self, cosign_artifact, cosign_bundle, production_root
    ):
        verifier = Verifier.from_root(production_root)
        policy = Identity("wrong@example.com", issuer=COSIGN_ISSUER)
        with pytest.raises(VerificationError) as exc_info:
            verifier.verify_artifact(cosign_artifact, cosign_bundle, policy)
        assert str(exc_info.value) != ""


class TestVerifyDsse:
    def test_verify_dsse_conda_succeeds(
        self, conda_artifact, conda_bundle, production_root
    ):
        verifier = Verifier.from_root(production_root)
        policy = Identity(CONDA_IDENTITY, issuer=CONDA_ISSUER)
        result = verifier.verify_dsse(conda_artifact, conda_bundle, policy)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_verify_dsse_payload_type(
        self, conda_artifact, conda_bundle, production_root
    ):
        verifier = Verifier.from_root(production_root)
        policy = Identity(CONDA_IDENTITY, issuer=CONDA_ISSUER)
        payload_type, payload_bytes = verifier.verify_dsse(
            conda_artifact, conda_bundle, policy
        )
        assert payload_type == "application/vnd.in-toto+json"

    def test_verify_dsse_payload_bytes_is_bytes(
        self, conda_artifact, conda_bundle, production_root
    ):
        verifier = Verifier.from_root(production_root)
        policy = Identity(CONDA_IDENTITY, issuer=CONDA_ISSUER)
        payload_type, payload_bytes = verifier.verify_dsse(
            conda_artifact, conda_bundle, policy
        )
        assert isinstance(payload_bytes, bytes)
        assert len(payload_bytes) > 0

    def test_verify_dsse_wrong_artifact_raises(
        self, conda_bundle, production_root
    ):
        verifier = Verifier.from_root(production_root)
        policy = Identity(CONDA_IDENTITY, issuer=CONDA_ISSUER)
        with pytest.raises(VerificationError):
            verifier.verify_dsse(b"tampered content", conda_bundle, policy)

    def test_verify_dsse_on_message_sig_bundle_raises(
        self, cosign_artifact, cosign_bundle, production_root
    ):
        """verify_dsse() called on a MessageSignature bundle must raise VerificationError."""
        verifier = Verifier.from_root(production_root)
        policy = Identity(COSIGN_IDENTITY, issuer=COSIGN_ISSUER)
        with pytest.raises(VerificationError):
            verifier.verify_dsse(cosign_artifact, cosign_bundle, policy)


class TestConvenienceVerify:
    def test_verify_with_bundle_object(
        self, cosign_artifact, cosign_bundle, production_root
    ):
        result = verify(
            cosign_artifact,
            cosign_bundle,
            identity=COSIGN_IDENTITY,
            issuer=COSIGN_ISSUER,
            trusted_root=production_root,
        )
        assert result is None

    def test_verify_with_json_string(
        self, cosign_artifact, cosign_bundle_json, production_root
    ):
        result = verify(
            cosign_artifact,
            cosign_bundle_json,
            identity=COSIGN_IDENTITY,
            issuer=COSIGN_ISSUER,
            trusted_root=production_root,
        )
        assert result is None

    def test_verify_wrong_bundle_type_raises(self, cosign_artifact, production_root):
        with pytest.raises(TypeError):
            verify(
                cosign_artifact,
                42,  # type: ignore[arg-type]
                identity=COSIGN_IDENTITY,
                trusted_root=production_root,
            )

    def test_verify_wrong_identity_raises(
        self, cosign_artifact, cosign_bundle, production_root
    ):
        with pytest.raises(VerificationError):
            verify(
                cosign_artifact,
                cosign_bundle,
                identity="wrong@example.com",
                trusted_root=production_root,
            )


@pytest.mark.network
class TestVerifierNetwork:
    def test_production(self):
        verifier = Verifier.production()
        assert verifier is not None

    def test_staging(self):
        verifier = Verifier.staging()
        assert verifier is not None
