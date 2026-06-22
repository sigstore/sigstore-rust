"""Tests for the Bundle Python API."""
import pytest

from sigstore import Bundle, BundleError


class TestBundleParsing:
    def test_from_json_cosign_v03(self, cosign_bundle_json):
        bundle = Bundle.from_json(cosign_bundle_json)
        assert "v0.3" in bundle.media_type

    def test_from_json_dsse_v01(self, dsse_bundle_json):
        bundle = Bundle.from_json(dsse_bundle_json)
        assert "0.1" in bundle.media_type

    def test_from_json_happy_path(self, happy_path_bundle_json):
        bundle = Bundle.from_json(happy_path_bundle_json)
        assert bundle is not None

    def test_media_type_is_str(self, cosign_bundle_json):
        bundle = Bundle.from_json(cosign_bundle_json)
        assert isinstance(bundle.media_type, str)
        assert len(bundle.media_type) > 0

    def test_from_json_invalid_raises(self):
        with pytest.raises(BundleError):
            Bundle.from_json("not json at all")

    def test_from_json_empty_raises(self):
        with pytest.raises(BundleError):
            Bundle.from_json("")

    def test_from_json_wrong_type_raises(self):
        with pytest.raises(TypeError):
            Bundle.from_json(123)  # type: ignore[arg-type]


class TestBundleSerialization:
    def test_to_json_roundtrip(self, cosign_bundle_json):
        original = Bundle.from_json(cosign_bundle_json)
        serialized = original.to_json()
        assert isinstance(serialized, str)
        restored = Bundle.from_json(serialized)
        assert restored.media_type == original.media_type

    def test_to_json_returns_str_not_bytes(self, cosign_bundle_json):
        bundle = Bundle.from_json(cosign_bundle_json)
        result = bundle.to_json()
        assert isinstance(result, str)

    def test_to_json_is_valid_json(self, cosign_bundle_json):
        import json
        bundle = Bundle.from_json(cosign_bundle_json)
        data = json.loads(bundle.to_json())
        assert "mediaType" in data


class TestBundleRepr:
    def test_repr_starts_with_bundle(self, cosign_bundle_json):
        bundle = Bundle.from_json(cosign_bundle_json)
        assert repr(bundle).startswith("Bundle(")

    def test_repr_contains_media_type(self, cosign_bundle_json):
        bundle = Bundle.from_json(cosign_bundle_json)
        assert "media_type" in repr(bundle)
