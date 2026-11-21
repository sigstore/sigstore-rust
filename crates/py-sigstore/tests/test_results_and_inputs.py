"""Tests for VerificationResult, Hashed inputs, policy flags and Bundle accessors."""
import datetime
import hashlib

import pytest

from py_sigstore import (
    Bundle,
    Hashed,
    Identity,
    TrustedRoot,
    VerificationResult,
    Verifier,
)

from .conftest import COSIGN_IDENTITY, COSIGN_ISSUER


@pytest.fixture(scope="module")
def verifier(production_root_json):
    return Verifier.from_root(TrustedRoot.from_json(production_root_json))


@pytest.fixture(scope="module")
def cosign_bundle(cosign_bundle_json):
    return Bundle.from_json(cosign_bundle_json)


class TestVerificationResult:
    def test_fields(self, verifier, cosign_bundle, cosign_artifact):
        result = verifier.verify_artifact(
            cosign_artifact, cosign_bundle, Identity(COSIGN_IDENTITY, COSIGN_ISSUER)
        )
        assert isinstance(result, VerificationResult)
        assert result.identity == COSIGN_IDENTITY
        assert result.issuer == COSIGN_ISSUER
        assert result.certificate_verified
        assert result.tlog_verified
        assert result.identity_policy_checked
        assert isinstance(result.verified_timestamps, list)

    def test_integrated_time_is_aware_utc_datetime(
        self, verifier, cosign_bundle, cosign_artifact
    ):
        result = verifier.verify_artifact(
            cosign_artifact, cosign_bundle, Identity(COSIGN_IDENTITY, COSIGN_ISSUER)
        )
        t = result.integrated_time
        if t is not None:
            assert isinstance(t, datetime.datetime)
            assert t.tzinfo is not None
            assert t.utcoffset() == datetime.timedelta(0)

    def test_repr_is_pythonic(self, verifier, cosign_bundle, cosign_artifact):
        r = repr(
            verifier.verify_artifact(
                cosign_artifact, cosign_bundle, Identity(COSIGN_IDENTITY, COSIGN_ISSUER)
            )
        )
        assert "Some(" not in r and "true" not in r


class TestHashed:
    def test_verify_with_digest(self, verifier, cosign_bundle, cosign_artifact):
        h = Hashed(hashlib.sha256(cosign_artifact).digest())
        result = verifier.verify_artifact(
            h, cosign_bundle, Identity(COSIGN_IDENTITY, COSIGN_ISSUER)
        )
        assert result.identity == COSIGN_IDENTITY

    def test_wrong_digest_fails(self, verifier, cosign_bundle):
        from py_sigstore import VerificationError

        h = Hashed(hashlib.sha256(b"something else").digest())
        with pytest.raises(VerificationError):
            verifier.verify_artifact(
                h, cosign_bundle, Identity(COSIGN_IDENTITY, COSIGN_ISSUER)
            )

    def test_from_hex_and_properties(self):
        d = hashlib.sha512(b"x")
        h = Hashed.from_hex(d.hexdigest(), "sha512")
        assert h.algorithm == "sha512"
        assert h.digest == d.digest()
        assert h == Hashed(d.digest(), "sha512")

    def test_bad_length_raises_value_error(self):
        with pytest.raises(ValueError):
            Hashed(b"short")

    def test_bad_algorithm_raises_value_error(self):
        with pytest.raises(ValueError):
            Hashed(b"\x00" * 32, "md5")

    def test_bad_artifact_type_raises_type_error(self, verifier, cosign_bundle):
        with pytest.raises(TypeError):
            verifier.verify_artifact(
                "not bytes", cosign_bundle, Identity(COSIGN_IDENTITY)
            )


class TestIdentityFlags:
    def test_flags_accepted(self):
        p = Identity("a@example.com", "https://issuer", skip_sct=True, skip_tlog_unsafe=True)
        assert p.identity == "a@example.com"
        assert p.issuer == "https://issuer"

    def test_flags_are_keyword_only(self):
        with pytest.raises(TypeError):
            Identity("a@example.com", "https://issuer", True)  # type: ignore[misc]


class TestBundleAccessors:
    def test_certificate_pem(self, cosign_bundle):
        pem = cosign_bundle.signing_certificate_pem
        assert pem is not None and pem.startswith("-----BEGIN CERTIFICATE-----")

    def test_inclusion_flags_and_kind(self, cosign_bundle):
        assert cosign_bundle.has_inclusion_proof
        assert isinstance(cosign_bundle.has_inclusion_promise, bool)
        assert cosign_bundle.is_dsse is False

    def test_dsse_bundle_is_dsse(self, dsse_bundle_json):
        assert Bundle.from_json(dsse_bundle_json).is_dsse is True

    def test_to_json_pretty_roundtrip(self, cosign_bundle):
        pretty = cosign_bundle.to_json_pretty()
        assert "\n" in pretty
        assert Bundle.from_json(pretty).to_json() == cosign_bundle.to_json()
