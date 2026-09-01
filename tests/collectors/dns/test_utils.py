"""
Tests for collectors/dns/utils.py.

Pure functions, no DNS I/O and no mocking required.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from collectors.dns.exceptions import InvalidTargetError
from collectors.dns.models import TargetType
from collectors.dns.utils import classify_target, normalize_dns_name, utc_now_iso


class TestClassifyTarget:
    def test_plain_domain(self):
        target = classify_target("example.com")
        assert target.value == "example.com"
        assert target.type == TargetType.DOMAIN

    def test_trailing_dot_is_stripped(self):
        target = classify_target("example.com.")
        assert target.value == "example.com"

    def test_uppercase_is_lowercased(self):
        target = classify_target("EXAMPLE.com")
        assert target.value == "example.com"

    def test_single_label_is_hostname(self):
        target = classify_target("localhost")
        assert target.type == TargetType.HOSTNAME

    def test_subdomain_is_domain(self):
        target = classify_target("mail.example.com")
        assert target.value == "mail.example.com"
        assert target.type == TargetType.DOMAIN

    def test_ipv4_is_classified_as_ip(self):
        target = classify_target("93.184.216.34")
        assert target.type == TargetType.IP
        assert target.value == "93.184.216.34"

    def test_ipv6_is_classified_as_ip(self):
        target = classify_target("2606:2800:220:1:248:1893:25c8:1946")
        assert target.type == TargetType.IP

    def test_surrounding_whitespace_is_trimmed(self):
        target = classify_target("  example.com  ")
        assert target.value == "example.com"

    def test_empty_string_is_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("")

    def test_whitespace_only_is_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("   ")

    def test_non_string_is_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target(12345)  # type: ignore[arg-type]

    def test_url_with_scheme_is_rejected_not_normalized(self):
        # The collector must not silently strip a scheme and resolve the
        # wrong thing -- a URL is not a valid DNS target.
        with pytest.raises(InvalidTargetError):
            classify_target("https://example.com")

    def test_url_with_path_is_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("https://example.com/path")

    def test_malformed_domain_is_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("not a valid host!!")

    def test_label_over_63_chars_is_rejected(self):
        label = "a" * 64
        with pytest.raises(InvalidTargetError):
            classify_target(f"{label}.com")

    def test_name_over_253_chars_is_rejected(self):
        long_name = ".".join(["a" * 50] * 6)
        assert len(long_name) > 253
        with pytest.raises(InvalidTargetError):
            classify_target(long_name)

    def test_leading_hyphen_label_is_rejected(self):
        with pytest.raises(InvalidTargetError):
            classify_target("-example.com")


class TestNormalizeDnsName:
    def test_strips_trailing_dot(self):
        assert normalize_dns_name("example.com.") == "example.com"

    def test_lowercases(self):
        assert normalize_dns_name("EXAMPLE.COM") == "example.com"

    def test_preserves_dns_root(self):
        # "." is meaningful on its own (e.g. a null MX target) and must
        # not be reduced to an empty string.
        assert normalize_dns_name(".") == "."

    def test_strips_surrounding_whitespace(self):
        assert normalize_dns_name("  example.com.  ") == "example.com"


class TestUtcNowIso:
    def test_is_a_parseable_utc_timestamp(self):
        value = utc_now_iso()
        assert value.endswith("Z")
        datetime.fromisoformat(value.replace("Z", "+00:00"))
