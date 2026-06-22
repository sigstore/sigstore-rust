"""Tests for the TrustedRoot Python API."""
import pytest

from sigstore import TrustedRoot, TrustedRootError


class TestTrustedRootOffline:
    def test_github_offline(self):
        """TrustedRoot.github() uses an embedded root — no network required."""
        root = TrustedRoot.github()
        assert root is not None

    def test_from_json_valid(self, production_root_json):
        root = TrustedRoot.from_json(production_root_json)
        assert root is not None

    def test_from_json_garbage_raises(self):
        with pytest.raises(TrustedRootError):
            TrustedRoot.from_json("{}")

    def test_from_json_empty_raises(self):
        with pytest.raises(TrustedRootError):
            TrustedRoot.from_json("")

    def test_from_json_not_json_raises(self):
        with pytest.raises(TrustedRootError):
            TrustedRoot.from_json("not json")

    def test_from_file_valid(self, fixture_root_path):
        root = TrustedRoot.from_file(fixture_root_path)
        assert root is not None

    def test_from_file_missing_raises(self):
        with pytest.raises(TrustedRootError):
            TrustedRoot.from_file("/nonexistent/path/trusted_root.json")


class TestTrustedRootRepr:
    def test_repr_starts_with_trusted_root(self):
        root = TrustedRoot.github()
        assert repr(root).startswith("TrustedRoot(")

    def test_repr_contains_counts(self):
        root = TrustedRoot.github()
        r = repr(root)
        assert "tlogs=" in r
        assert "cas=" in r


@pytest.mark.network
class TestTrustedRootNetwork:
    def test_production(self):
        root = TrustedRoot.production()
        assert root is not None

    def test_staging(self):
        root = TrustedRoot.staging()
        assert root is not None
