"""
Tests for collectors/certificates/utils.py.

Pure functions, no network I/O and no mocking required.
"""

from __future__ import annotations

import pytest

from collectors.certificates.exceptions import InvalidTargetError
from collectors.certificates.models import CertificateValidityStatus
from collectors.certificates.utils import (
    classify_target,
    compute_validity_status,
    normalize_dns_name,
    parse_ct_timestamp,
)


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

    def test_bare_path_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("example.com/path")

    def test_ipv4_rejected(self):
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

    def test_trailing_dot_hostname_accepted(self):
        assert classify_target("www.example.com.").value == "www.example.com"


class TestNormalizeDnsName:
    def test_basic(self):
        san = normalize_dns_name("api.example.com")
        assert san.name == "api.example.com"
        assert san.is_wildcard is False
        assert san.raw == "api.example.com"

    def test_uppercase_lowercased(self):
        san = normalize_dns_name("API.Example.COM")
        assert san.name == "api.example.com"

    def test_trailing_dot_stripped(self):
        san = normalize_dns_name("api.example.com.")
        assert san.name == "api.example.com"

    def test_wildcard_prefix_recognized_and_preserved(self):
        san = normalize_dns_name("*.example.com")
        assert san.name == "example.com"
        assert san.is_wildcard is True
        assert san.raw == "*.example.com"

    def test_bare_wildcard_is_invalid(self):
        assert normalize_dns_name("*.") is None

    def test_wildcard_case_preserved_in_raw_but_name_lowercased(self):
        san = normalize_dns_name("*.API.Example.COM")
        assert san.name == "api.example.com"
        assert san.is_wildcard is True
        assert san.raw == "*.API.Example.COM"

    def test_non_string_returns_none(self):
        assert normalize_dns_name(None) is None  # type: ignore[arg-type]

    def test_empty_string_returns_none(self):
        assert normalize_dns_name("") is None

    def test_whitespace_only_returns_none(self):
        assert normalize_dns_name("   ") is None

    def test_email_like_san_returns_none(self):
        assert normalize_dns_name("admin@example.com") is None

    def test_ip_address_san_returns_none(self):
        assert normalize_dns_name("192.0.2.1") is None

    def test_ipv6_san_returns_none(self):
        assert normalize_dns_name("2606:2800:220:1::1") is None

    def test_label_over_63_chars_returns_none(self):
        assert normalize_dns_name("a" * 64 + ".com") is None

    def test_name_over_253_chars_returns_none(self):
        assert normalize_dns_name(".".join(["a" * 50] * 6)) is None

    def test_malformed_characters_return_none(self):
        assert normalize_dns_name("not a valid host!!") is None

    def test_duplicate_case_variants_normalize_identically(self):
        assert normalize_dns_name("API.example.com").name == normalize_dns_name("api.EXAMPLE.com").name


class TestParseCtTimestamp:
    def test_basic_timestamp(self):
        assert parse_ct_timestamp("2026-01-01T00:00:00") == "2026-01-01T00:00:00.000Z"

    def test_timestamp_with_fractional_seconds(self):
        assert parse_ct_timestamp("2026-01-01T12:30:45.123") == "2026-01-01T12:30:45.123Z"

    def test_timestamp_with_z_suffix(self):
        assert parse_ct_timestamp("2026-01-01T00:00:00Z") == "2026-01-01T00:00:00.000Z"

    def test_none_returns_none(self):
        assert parse_ct_timestamp(None) is None

    def test_empty_string_returns_none(self):
        assert parse_ct_timestamp("") is None

    def test_whitespace_only_returns_none(self):
        assert parse_ct_timestamp("   ") is None

    def test_malformed_timestamp_returns_none(self):
        assert parse_ct_timestamp("not a date") is None

    def test_non_string_returns_none(self):
        assert parse_ct_timestamp(12345) is None  # type: ignore[arg-type]


class TestComputeValidityStatus:
    def test_current_certificate(self):
        status = compute_validity_status("2000-01-01T00:00:00.000Z", "2999-01-01T00:00:00.000Z")
        assert status == CertificateValidityStatus.CURRENT

    def test_expired_certificate(self):
        status = compute_validity_status("2000-01-01T00:00:00.000Z", "2001-01-01T00:00:00.000Z")
        assert status == CertificateValidityStatus.EXPIRED

    def test_not_yet_valid_certificate(self):
        status = compute_validity_status("2999-01-01T00:00:00.000Z", "3000-01-01T00:00:00.000Z")
        assert status == CertificateValidityStatus.NOT_YET_VALID

    def test_missing_not_before_is_unknown(self):
        assert compute_validity_status(None, "2999-01-01T00:00:00.000Z") == CertificateValidityStatus.UNKNOWN

    def test_missing_not_after_is_unknown(self):
        assert compute_validity_status("2000-01-01T00:00:00.000Z", None) == CertificateValidityStatus.UNKNOWN

    def test_both_missing_is_unknown(self):
        assert compute_validity_status(None, None) == CertificateValidityStatus.UNKNOWN

    def test_malformed_dates_are_unknown(self):
        assert compute_validity_status("not a date", "also not a date") == CertificateValidityStatus.UNKNOWN
