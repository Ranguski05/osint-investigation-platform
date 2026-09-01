"""
Tests for collectors/subdomains/sources/crtsh.py.

`urllib.request.urlopen` is mocked so nothing here touches the network.
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import patch

import pytest

from collectors.subdomains.exceptions import SourceError
from collectors.subdomains.sources.crtsh import CrtShSource


class FakeResponse:
    """Minimal stand-in for the context-manager object urlopen() returns."""

    def __init__(self, body: bytes):
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def json_response(data) -> FakeResponse:
    return FakeResponse(json.dumps(data).encode("utf-8"))


class TestCrtShSourceSuccess:
    def test_single_certificate_single_name(self):
        source = CrtShSource()
        data = [{"id": 123, "name_value": "api.example.com"}]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert len(candidates) == 1
        assert candidates[0].hostname == "api.example.com"
        assert candidates[0].source_reference == "123"

    def test_multiple_names_in_one_certificate(self):
        source = CrtShSource()
        data = [{"id": 1, "name_value": "example.com\nwww.example.com\napi.example.com"}]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        hostnames = {candidate.hostname for candidate in candidates}
        assert hostnames == {"example.com", "www.example.com", "api.example.com"}
        # All three came from the same certificate.
        assert {candidate.source_reference for candidate in candidates} == {"1"}

    def test_multiple_certificates(self):
        source = CrtShSource()
        data = [
            {"id": 1, "name_value": "a.example.com"},
            {"id": 2, "name_value": "b.example.com"},
        ]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert len(candidates) == 2

    def test_duplicate_names_across_certificates_are_both_reported(self):
        # Deduplication is the collector's job, not the source's -- the
        # source should faithfully report every raw occurrence so the
        # collector can preserve multi-source/multi-certificate provenance.
        source = CrtShSource()
        data = [
            {"id": 1, "name_value": "api.example.com"},
            {"id": 2, "name_value": "api.example.com"},
        ]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert len(candidates) == 2

    def test_wildcard_name_is_passed_through_unmodified(self):
        # Wildcard normalization happens in utils.normalize_hostname, not
        # in the source -- the source just reports what crt.sh returned.
        source = CrtShSource()
        data = [{"id": 1, "name_value": "*.example.com"}]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert candidates[0].hostname == "*.example.com"

    def test_empty_response(self):
        source = CrtShSource()

        with patch("urllib.request.urlopen", return_value=json_response([])):
            candidates = source.enumerate("example.com", timeout=5)

        assert candidates == []

    def test_entry_missing_name_value_is_skipped(self):
        source = CrtShSource()
        data = [{"id": 1}, {"id": 2, "name_value": "api.example.com"}]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert len(candidates) == 1
        assert candidates[0].hostname == "api.example.com"

    def test_missing_id_yields_none_source_reference(self):
        source = CrtShSource()
        data = [{"name_value": "api.example.com"}]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert candidates[0].source_reference is None

    def test_non_dict_entries_are_skipped(self):
        source = CrtShSource()
        data = ["not a dict", {"id": 1, "name_value": "api.example.com"}]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert len(candidates) == 1


class TestCrtShSourceFailure:
    def test_http_error_raises_source_error(self):
        source = CrtShSource()
        http_error = urllib.error.HTTPError("https://crt.sh/", 502, "Bad Gateway", {}, None)

        with patch("urllib.request.urlopen", side_effect=http_error):
            with pytest.raises(SourceError):
                source.enumerate("example.com", timeout=5)

    def test_url_error_raises_source_error(self):
        source = CrtShSource()

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
            with pytest.raises(SourceError):
                source.enumerate("example.com", timeout=5)

    def test_malformed_json_raises_source_error(self):
        source = CrtShSource()
        bad_response = FakeResponse(b"<html>502 Bad Gateway</html>")

        with patch("urllib.request.urlopen", return_value=bad_response):
            with pytest.raises(SourceError):
                source.enumerate("example.com", timeout=5)

    def test_unexpected_json_shape_raises_source_error(self):
        source = CrtShSource()

        with patch("urllib.request.urlopen", return_value=json_response({"not": "a list"})):
            with pytest.raises(SourceError):
                source.enumerate("example.com", timeout=5)

    def test_source_error_never_leaks_a_raw_dnspython_or_urllib_exception(self):
        # Callers (the collector) only need to catch SourceError.
        source = CrtShSource()

        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with pytest.raises(SourceError):
                source.enumerate("example.com", timeout=5)
