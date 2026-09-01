"""
Tests for collectors/subdomains/utils.py.

Pure functions, no network I/O and no mocking required.
"""

from __future__ import annotations

import pytest

from collectors.subdomains.exceptions import InvalidTargetError
from collectors.subdomains.utils import classify_target, is_in_scope, normalize_hostname


class TestClassifyTarget:
    def test_valid_domain(self):
        assert classify_target("example.com").value == "example.com"

    def test_trailing_dot_stripped(self):
        assert classify_target("example.com.").value == "example.com"

    def test_uppercase_lowercased(self):
        assert classify_target("EXAMPLE.COM").value == "example.com"

    def test_whitespace_trimmed(self):
        assert classify_target("  example.com  ").value == "example.com"

    def test_empty_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("")

    def test_whitespace_only_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("   ")

    def test_non_string_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target(123)  # type: ignore[arg-type]

    def test_malformed_domain_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("not a valid host!!")

    def test_url_with_scheme_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("https://example.com")

    def test_url_with_path_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("https://example.com/path")

    def test_ipv4_rejected(self):
        # Subdomain enumeration is a domain concept -- an IP target
        # doesn't make sense here (see collectors/dns for IP handling).
        with pytest.raises(InvalidTargetError):
            classify_target("93.184.216.34")

    def test_ipv6_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("2606:2800:220:1:248:1893:25c8:1946")

    def test_label_over_63_chars_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("a" * 64 + ".com")

    def test_name_over_253_chars_rejected(self):
        long_name = ".".join(["a" * 50] * 6)
        assert len(long_name) > 253
        with pytest.raises(InvalidTargetError):
            classify_target(long_name)


class TestNormalizeHostname:
    def test_basic(self):
        assert normalize_hostname("api.example.com") == "api.example.com"

    def test_uppercase_lowercased(self):
        assert normalize_hostname("API.Example.COM") == "api.example.com"

    def test_trailing_dot_stripped(self):
        assert normalize_hostname("api.example.com.") == "api.example.com"

    def test_wildcard_prefix_stripped(self):
        assert normalize_hostname("*.api.example.com") == "api.example.com"

    def test_bare_wildcard_is_invalid(self):
        assert normalize_hostname("*.") is None

    def test_non_string_returns_none(self):
        assert normalize_hostname(None) is None  # type: ignore[arg-type]

    def test_empty_string_returns_none(self):
        assert normalize_hostname("") is None

    def test_whitespace_only_returns_none(self):
        assert normalize_hostname("   ") is None

    def test_email_like_san_returns_none(self):
        # Some certificates list an email address as a SAN; that is not
        # a hostname and must not be treated as one.
        assert normalize_hostname("admin@example.com") is None

    def test_label_over_63_chars_returns_none(self):
        assert normalize_hostname("a" * 64 + ".com") is None

    def test_name_over_253_chars_returns_none(self):
        assert normalize_hostname(".".join(["a" * 50] * 6)) is None


class TestIsInScope:
    def test_exact_match_is_in_scope(self):
        assert is_in_scope("example.com", "example.com") is True

    def test_direct_subdomain_is_in_scope(self):
        assert is_in_scope("www.example.com", "example.com") is True

    def test_nested_subdomain_is_in_scope(self):
        assert is_in_scope("foo.bar.example.com", "example.com") is True

    def test_sibling_suffix_domain_is_rejected(self):
        assert is_in_scope("example.com.attacker.com", "example.com") is False

    def test_lookalike_prefix_domain_is_rejected(self):
        assert is_in_scope("attackerexample.com", "example.com") is False

    def test_different_tld_is_rejected(self):
        assert is_in_scope("example.org", "example.com") is False

    def test_unrelated_domain_is_rejected(self):
        assert is_in_scope("evil.net", "example.com") is False

    def test_case_insensitive(self):
        assert is_in_scope("WWW.EXAMPLE.COM", "example.com") is True

    def test_trailing_dots_handled(self):
        assert is_in_scope("www.example.com.", "example.com.") is True
