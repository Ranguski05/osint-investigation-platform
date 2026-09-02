"""
Tests for collectors/subdomains/sources/certspotter.py.

`urllib.request.urlopen` is mocked so nothing here touches the network,
same approach as test_sources_crtsh.py.
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import patch

import pytest

from collectors.subdomains.exceptions import SourceError
from collectors.subdomains.sources.certspotter import MAX_PAGES, PAGE_SIZE, CertSpotterSource


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


def issuance(issuance_id: str, dns_names: list[str]) -> dict:
    return {"id": issuance_id, "dns_names": dns_names}


class TestCertSpotterSourceSuccess:
    def test_single_issuance_single_name(self):
        source = CertSpotterSource()
        data = [issuance("1", ["api.example.com"])]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert len(candidates) == 1
        assert candidates[0].hostname == "api.example.com"
        assert candidates[0].source_reference == "1"

    def test_multiple_names_in_one_issuance(self):
        source = CertSpotterSource()
        data = [issuance("1", ["example.com", "www.example.com", "api.example.com"])]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        hostnames = {candidate.hostname for candidate in candidates}
        assert hostnames == {"example.com", "www.example.com", "api.example.com"}
        assert {candidate.source_reference for candidate in candidates} == {"1"}

    def test_multiple_issuances(self):
        source = CertSpotterSource()
        data = [issuance("1", ["a.example.com"]), issuance("2", ["b.example.com"])]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert len(candidates) == 2

    def test_duplicate_names_across_issuances_are_both_reported(self):
        # Deduplication is the collector's job, not the source's.
        source = CertSpotterSource()
        data = [issuance("1", ["api.example.com"]), issuance("2", ["api.example.com"])]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert len(candidates) == 2

    def test_wildcard_name_is_passed_through_unmodified(self):
        # Wildcard normalization happens centrally in utils.normalize_hostname.
        source = CertSpotterSource()
        data = [issuance("1", ["*.example.com"])]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert candidates[0].hostname == "*.example.com"

    def test_out_of_scope_names_are_passed_through_unfiltered(self):
        # Scope validation is the collector's job (utils.is_in_scope),
        # applied to every source's raw output uniformly -- the source
        # itself must not try to filter.
        source = CertSpotterSource()
        data = [issuance("1", ["evil-example.com"])]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert candidates[0].hostname == "evil-example.com"

    def test_empty_response(self):
        source = CertSpotterSource()

        with patch("urllib.request.urlopen", return_value=json_response([])):
            candidates = source.enumerate("example.com", timeout=5)

        assert candidates == []

    def test_entry_missing_dns_names_is_skipped(self):
        source = CertSpotterSource()
        data = [{"id": "1"}, issuance("2", ["api.example.com"])]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert len(candidates) == 1
        assert candidates[0].hostname == "api.example.com"

    def test_non_dict_entries_are_skipped(self):
        source = CertSpotterSource()
        data = ["not a dict", issuance("1", ["api.example.com"])]

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert len(candidates) == 1

    def test_api_key_is_sent_as_basic_auth(self):
        source = CertSpotterSource(api_key="secret-token")
        captured_requests = []

        def fake_urlopen(request, timeout):
            captured_requests.append(request)
            return json_response([])

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            source.enumerate("example.com", timeout=5)

        assert len(captured_requests) == 1
        auth_header = captured_requests[0].get_header("Authorization")
        assert auth_header is not None and auth_header.startswith("Basic ")

    def test_no_api_key_sends_no_auth_header(self):
        source = CertSpotterSource()
        captured_requests = []

        def fake_urlopen(request, timeout):
            captured_requests.append(request)
            return json_response([])

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            source.enumerate("example.com", timeout=5)

        assert captured_requests[0].get_header("Authorization") is None

    def test_pagination_follows_after_cursor_until_short_page(self):
        full_page = [issuance(str(i), [f"h{i}.example.com"]) for i in range(PAGE_SIZE)]
        short_page = [issuance("last", ["tail.example.com"])]

        with patch("urllib.request.urlopen", side_effect=[json_response(full_page), json_response(short_page)]):
            candidates = CertSpotterSource().enumerate("example.com", timeout=5)

        assert len(candidates) == PAGE_SIZE + 1
        assert candidates[-1].hostname == "tail.example.com"

    def test_pagination_stops_at_max_pages_even_if_every_page_is_full(self):
        full_page = [issuance(str(i), [f"h{i}.example.com"]) for i in range(PAGE_SIZE)]

        with patch("urllib.request.urlopen", return_value=json_response(full_page)) as mock_urlopen:
            CertSpotterSource().enumerate("example.com", timeout=5)

        assert mock_urlopen.call_count == MAX_PAGES

    def test_single_short_page_does_not_trigger_a_second_request(self):
        with patch("urllib.request.urlopen", return_value=json_response([issuance("1", ["api.example.com"])])) as mock_urlopen:
            CertSpotterSource().enumerate("example.com", timeout=5)

        assert mock_urlopen.call_count == 1


class TestCertSpotterSourceFailure:
    def test_generic_http_error_raises_source_error(self):
        source = CertSpotterSource()
        http_error = urllib.error.HTTPError("https://api.certspotter.com/", 502, "Bad Gateway", {}, None)

        with patch("urllib.request.urlopen", side_effect=http_error):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "SOURCE_ERROR"

    def test_rate_limit_raises_rate_limited_error_type(self):
        source = CertSpotterSource()
        http_error = urllib.error.HTTPError("https://api.certspotter.com/", 429, "Too Many Requests", {}, None)

        with patch("urllib.request.urlopen", side_effect=http_error):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "RATE_LIMITED"

    def test_invalid_api_key_raises_auth_error_type(self):
        source = CertSpotterSource(api_key="bad-key")
        http_error = urllib.error.HTTPError("https://api.certspotter.com/", 403, "Forbidden", {}, None)

        with patch("urllib.request.urlopen", side_effect=http_error):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "AUTH_ERROR"

    def test_url_error_raises_network_error_type(self):
        source = CertSpotterSource()

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "NETWORK_ERROR"

    def test_timeout_raises_timeout_error_type(self):
        source = CertSpotterSource()

        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "TIMEOUT"

    def test_malformed_json_raises_malformed_response_error_type(self):
        source = CertSpotterSource()
        bad_response = FakeResponse(b"<html>502 Bad Gateway</html>")

        with patch("urllib.request.urlopen", return_value=bad_response):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "MALFORMED_RESPONSE"

    def test_unexpected_json_shape_raises_malformed_response_error_type(self):
        source = CertSpotterSource()

        with patch("urllib.request.urlopen", return_value=json_response({"not": "a list"})):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "MALFORMED_RESPONSE"

    def test_source_error_never_leaks_a_raw_urllib_exception(self):
        source = CertSpotterSource()

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("boom")):
            with pytest.raises(SourceError):
                source.enumerate("example.com", timeout=5)
