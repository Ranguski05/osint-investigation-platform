"""
Tests for collectors/subdomains/sources/securitytrails.py.

`urllib.request.urlopen` is mocked so nothing here touches the network,
same approach as test_sources_crtsh.py. `OSINT_SECURITYTRAILS_API_KEY` is
patched out of os.environ for every test (via the autouse fixture below)
so a developer's real environment can never leak into a test run.
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import patch

import pytest

from collectors.subdomains.exceptions import SourceError
from collectors.subdomains.sources.securitytrails import API_KEY_ENV_VAR, SecurityTrailsSource


class FakeResponse:
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


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)


class TestSecurityTrailsSourceSuccess:
    def test_labels_are_joined_onto_the_domain(self):
        source = SecurityTrailsSource(api_key="key")
        data = {"subdomains": ["api", "www"]}

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        hostnames = {c.hostname for c in candidates}
        assert hostnames == {"api.example.com", "www.example.com"}

    def test_source_reference_is_the_raw_label(self):
        source = SecurityTrailsSource(api_key="key")
        data = {"subdomains": ["api"]}

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert candidates[0].source_reference == "api"

    def test_multiple_subdomains(self):
        source = SecurityTrailsSource(api_key="key")
        data = {"subdomains": ["a", "b", "c"]}

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert len(candidates) == 3

    def test_duplicate_labels_are_both_reported(self):
        # Deduplication is the collector's job, not the source's.
        source = SecurityTrailsSource(api_key="key")
        data = {"subdomains": ["api", "api"]}

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        assert len(candidates) == 2

    def test_empty_subdomains_is_a_successful_empty_result(self):
        source = SecurityTrailsSource(api_key="key")

        with patch("urllib.request.urlopen", return_value=json_response({"subdomains": []})):
            candidates = source.enumerate("example.com", timeout=5)

        assert candidates == []

    def test_blank_and_non_string_labels_are_skipped(self):
        source = SecurityTrailsSource(api_key="key")
        data = {"subdomains": ["api", "", "  ", 123, None, "www"]}

        with patch("urllib.request.urlopen", return_value=json_response(data)):
            candidates = source.enumerate("example.com", timeout=5)

        hostnames = {c.hostname for c in candidates}
        assert hostnames == {"api.example.com", "www.example.com"}

    def test_api_key_from_constructor_is_sent_in_apikey_header(self):
        source = SecurityTrailsSource(api_key="explicit-key")
        captured_requests = []

        def fake_urlopen(request, timeout):
            captured_requests.append(request)
            return json_response({"subdomains": []})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            source.enumerate("example.com", timeout=5)

        assert captured_requests[0].get_header("Apikey") == "explicit-key"

    def test_api_key_falls_back_to_environment_variable(self, monkeypatch):
        monkeypatch.setenv(API_KEY_ENV_VAR, "env-key")
        source = SecurityTrailsSource()

        assert source.api_key == "env-key"

    def test_constructor_argument_takes_priority_over_environment_variable(self, monkeypatch):
        monkeypatch.setenv(API_KEY_ENV_VAR, "env-key")
        source = SecurityTrailsSource(api_key="explicit-key")

        assert source.api_key == "explicit-key"


class TestSecurityTrailsSourceAuthentication:
    def test_missing_api_key_raises_auth_error_without_a_network_call(self):
        source = SecurityTrailsSource()

        with patch("urllib.request.urlopen") as mock_urlopen:
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        mock_urlopen.assert_not_called()
        assert exc_info.value.error_type == "AUTH_ERROR"

    def test_rejected_api_key_raises_auth_error(self):
        source = SecurityTrailsSource(api_key="bad-key")
        http_error = urllib.error.HTTPError("https://api.securitytrails.com/", 401, "Unauthorized", {}, None)

        with patch("urllib.request.urlopen", side_effect=http_error):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "AUTH_ERROR"

    def test_forbidden_response_raises_auth_error(self):
        source = SecurityTrailsSource(api_key="bad-key")
        http_error = urllib.error.HTTPError("https://api.securitytrails.com/", 403, "Forbidden", {}, None)

        with patch("urllib.request.urlopen", side_effect=http_error):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "AUTH_ERROR"


class TestSecurityTrailsSourceFailure:
    def test_rate_limit_raises_rate_limited_error_type(self):
        source = SecurityTrailsSource(api_key="key")
        http_error = urllib.error.HTTPError("https://api.securitytrails.com/", 429, "Too Many Requests", {}, None)

        with patch("urllib.request.urlopen", side_effect=http_error):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "RATE_LIMITED"

    def test_timeout_raises_timeout_error_type(self):
        source = SecurityTrailsSource(api_key="key")

        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "TIMEOUT"

    def test_url_error_raises_network_error_type(self):
        source = SecurityTrailsSource(api_key="key")

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "NETWORK_ERROR"

    def test_generic_http_error_raises_source_error(self):
        source = SecurityTrailsSource(api_key="key")
        http_error = urllib.error.HTTPError("https://api.securitytrails.com/", 502, "Bad Gateway", {}, None)

        with patch("urllib.request.urlopen", side_effect=http_error):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "SOURCE_ERROR"

    def test_malformed_json_raises_malformed_response_error_type(self):
        source = SecurityTrailsSource(api_key="key")
        bad_response = FakeResponse(b"<html>502 Bad Gateway</html>")

        with patch("urllib.request.urlopen", return_value=bad_response):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "MALFORMED_RESPONSE"

    def test_missing_subdomains_key_raises_malformed_response_error_type(self):
        source = SecurityTrailsSource(api_key="key")

        with patch("urllib.request.urlopen", return_value=json_response({"unexpected": "shape"})):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "MALFORMED_RESPONSE"

    def test_subdomains_not_a_list_raises_malformed_response_error_type(self):
        source = SecurityTrailsSource(api_key="key")

        with patch("urllib.request.urlopen", return_value=json_response({"subdomains": "not-a-list"})):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "MALFORMED_RESPONSE"

    def test_response_not_a_dict_raises_malformed_response_error_type(self):
        source = SecurityTrailsSource(api_key="key")

        with patch("urllib.request.urlopen", return_value=json_response(["not", "a", "dict"])):
            with pytest.raises(SourceError) as exc_info:
                source.enumerate("example.com", timeout=5)

        assert exc_info.value.error_type == "MALFORMED_RESPONSE"

    def test_source_error_never_leaks_a_raw_urllib_exception(self):
        source = SecurityTrailsSource(api_key="key")

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("boom")):
            with pytest.raises(SourceError):
                source.enumerate("example.com", timeout=5)
