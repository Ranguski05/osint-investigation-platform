"""
Tests for collectors/certificates/sources/crtsh.py.

`urllib.request.urlopen` is mocked so nothing here touches the network.
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import patch

import pytest

from collectors.certificates.exceptions import SourceError
from collectors.certificates.sources.crtsh import CrtShSource


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
    def test_single_certificate(self):
        source = CrtShSource()
        data = [
            {
                "id": 123,
                "name_value": "example.com\nwww.example.com",
                "common_name": "example.com",
                "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                "serial_number": "abc123",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2026-04-01T00:00:00",
            }
        ]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            entries = source.search("example.com", timeout=5)

        assert len(entries) == 1
        entry = entries[0]
        assert entry.source_reference == "123"
        assert entry.name_value == "example.com\nwww.example.com"
        assert entry.common_name == "example.com"
        assert entry.issuer == "C=US, O=Let's Encrypt, CN=R3"
        assert entry.serial_number == "abc123"
        assert entry.not_before == "2026-01-01T00:00:00"
        assert entry.not_after == "2026-04-01T00:00:00"

    def test_multiple_certificates(self):
        source = CrtShSource()
        data = [
            {"id": 1, "name_value": "a.example.com"},
            {"id": 2, "name_value": "b.example.com"},
        ]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            entries = source.search("example.com", timeout=5)

        assert len(entries) == 2

    def test_wildcard_name_passed_through_unmodified(self):
        # Normalization happens in utils.normalize_dns_name, not the source.
        source = CrtShSource()
        data = [{"id": 1, "name_value": "*.example.com"}]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            entries = source.search("example.com", timeout=5)

        assert entries[0].name_value == "*.example.com"

    def test_empty_response(self):
        source = CrtShSource()

        with patch("urllib.request.urlopen", return_value=json_response([])):
            entries = source.search("example.com", timeout=5)

        assert entries == []

    def test_entry_missing_name_value_is_skipped(self):
        source = CrtShSource()
        data = [{"id": 1}, {"id": 2, "name_value": "api.example.com"}]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            entries = source.search("example.com", timeout=5)

        assert len(entries) == 1
        assert entries[0].source_reference == "2"

    def test_entry_missing_id_is_skipped(self):
        source = CrtShSource()
        data = [{"name_value": "api.example.com"}, {"id": 2, "name_value": "b.example.com"}]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            entries = source.search("example.com", timeout=5)

        assert len(entries) == 1
        assert entries[0].source_reference == "2"

    def test_non_dict_entries_are_skipped(self):
        source = CrtShSource()
        data = ["not a dict", {"id": 1, "name_value": "api.example.com"}]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            entries = source.search("example.com", timeout=5)

        assert len(entries) == 1

    def test_missing_optional_metadata_becomes_none(self):
        source = CrtShSource()
        data = [{"id": 1, "name_value": "api.example.com"}]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            entries = source.search("example.com", timeout=5)

        entry = entries[0]
        assert entry.common_name is None
        assert entry.issuer is None
        assert entry.serial_number is None
        assert entry.not_before is None
        assert entry.not_after is None

    def test_blank_optional_metadata_becomes_none(self):
        source = CrtShSource()
        data = [{"id": 1, "name_value": "api.example.com", "issuer_name": "   "}]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            entries = source.search("example.com", timeout=5)

        assert entries[0].issuer is None


class TestCrtShSourceFailure:
    def test_http_502_raises_source_error(self):
        source = CrtShSource()
        http_error = urllib.error.HTTPError("https://crt.sh/", 502, "Bad Gateway", {}, None)

        with patch("urllib.request.urlopen", side_effect=http_error):
            with pytest.raises(SourceError):
                source.search("example.com", timeout=5)

    def test_http_503_raises_source_error(self):
        source = CrtShSource()
        http_error = urllib.error.HTTPError("https://crt.sh/", 503, "Service Unavailable", {}, None)

        with patch("urllib.request.urlopen", side_effect=http_error):
            with pytest.raises(SourceError):
                source.search("example.com", timeout=5)

    def test_http_504_raises_source_error(self):
        source = CrtShSource()
        http_error = urllib.error.HTTPError("https://crt.sh/", 504, "Gateway Timeout", {}, None)

        with patch("urllib.request.urlopen", side_effect=http_error):
            with pytest.raises(SourceError):
                source.search("example.com", timeout=5)

    def test_url_error_raises_source_error(self):
        source = CrtShSource()

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
            with pytest.raises(SourceError):
                source.search("example.com", timeout=5)

    def test_timeout_raises_source_error(self):
        source = CrtShSource()

        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with pytest.raises(SourceError):
                source.search("example.com", timeout=5)

    def test_malformed_json_raises_source_error(self):
        source = CrtShSource()
        bad_response = FakeResponse(b"<html>502 Bad Gateway</html>")

        with patch("urllib.request.urlopen", return_value=bad_response):
            with pytest.raises(SourceError):
                source.search("example.com", timeout=5)

    def test_unexpected_json_shape_raises_source_error(self):
        source = CrtShSource()

        with patch("urllib.request.urlopen", return_value=json_response({"not": "a list"})):
            with pytest.raises(SourceError):
                source.search("example.com", timeout=5)

    def test_source_error_never_leaks_a_raw_urllib_exception(self):
        source = CrtShSource()

        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with pytest.raises(SourceError):
                source.search("example.com", timeout=5)
