"""
Tests for collectors/subdomains/dns_validation.py.

dns.resolver.Resolver.resolve is mocked at the class level (this module
creates its own Resolver instance internally, so there's no instance
reference to patch the way collectors/dns's own tests do) -- nothing here
touches the network. A small local fake Answer is used rather than
importing collectors/dns's test helpers, keeping the two collectors'
test suites independent too.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from collectors.subdomains.dns_validation import detect_wildcard_ips, validate_hostname
from collectors.subdomains.models import DnsValidationStatus


def make_rdata(record_type: str, text: str):
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(record_type), text)


class FakeAnswer:
    def __init__(self, name: str, ttl: int, rdata_list: list):
        self.name = dns.name.from_text(name)
        self.rrset = SimpleNamespace(ttl=ttl)
        self._rdata_list = rdata_list

    def __iter__(self):
        return iter(self._rdata_list)


class NoAnswerAnswer:
    rrset = None


def fake_resolve_factory(responses: dict):
    """responses: {(hostname_without_trailing_dot, record_type): Answer-like or Exception}"""

    def fake_resolve(name, record_type, raise_on_no_answer=False):
        key = (str(name).rstrip("."), record_type)
        result = responses.get(key, NoAnswerAnswer())
        if isinstance(result, Exception):
            raise result
        return result

    return fake_resolve


class TestValidateHostname:
    def test_a_record_resolves(self):
        responses = {("api.example.com", "A"): FakeAnswer("api.example.com", 300, [make_rdata("A", "1.2.3.4")])}

        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve_factory(responses)):
            status, records = validate_hostname("api.example.com", nameservers=None, timeout=1, lifetime=1)

        assert status == DnsValidationStatus.RESOLVED
        assert records[0].type == "A"
        assert records[0].value == "1.2.3.4"

    def test_aaaa_record_resolves(self):
        responses = {
            ("api.example.com", "AAAA"): FakeAnswer(
                "api.example.com", 300, [make_rdata("AAAA", "2606:2800:220:1:248:1893:25c8:1946")]
            )
        }

        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve_factory(responses)):
            status, records = validate_hostname("api.example.com", nameservers=None, timeout=1, lifetime=1)

        assert status == DnsValidationStatus.RESOLVED
        assert any(record.type == "AAAA" for record in records)

    def test_cname_record_resolves(self):
        responses = {("www.example.com", "CNAME"): FakeAnswer("www.example.com", 300, [make_rdata("CNAME", "example.com.")])}

        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve_factory(responses)):
            status, records = validate_hostname("www.example.com", nameservers=None, timeout=1, lifetime=1)

        assert status == DnsValidationStatus.RESOLVED
        assert records[0].type == "CNAME"
        assert records[0].value == "example.com"

    def test_unresolved_hostname(self):
        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve_factory({})):
            status, records = validate_hostname("nope.example.com", nameservers=None, timeout=1, lifetime=1)

        assert status == DnsValidationStatus.UNRESOLVED
        assert records == []

    def test_nxdomain_is_unresolved_not_an_exception(self):
        responses = {
            ("nope.example.com", record_type): dns.resolver.NXDOMAIN()
            for record_type in ("A", "AAAA", "CNAME")
        }

        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve_factory(responses)):
            status, records = validate_hostname("nope.example.com", nameservers=None, timeout=1, lifetime=1)

        assert status == DnsValidationStatus.UNRESOLVED
        assert records == []

    def test_timeout_is_unresolved_not_an_exception(self):
        with patch("dns.resolver.Resolver.resolve", side_effect=dns.exception.Timeout()):
            status, records = validate_hostname("slow.example.com", nameservers=None, timeout=1, lifetime=1)

        assert status == DnsValidationStatus.UNRESOLVED

    def test_resolver_error_is_unresolved_not_an_exception(self):
        fake_request = SimpleNamespace(question=["example.com IN A"])
        exc = dns.resolver.NoNameservers(request=fake_request, errors=[("8.8.8.8", False, 53, Exception("SERVFAIL"), None)])

        with patch("dns.resolver.Resolver.resolve", side_effect=exc):
            status, records = validate_hostname("slow.example.com", nameservers=None, timeout=1, lifetime=1)

        assert status == DnsValidationStatus.UNRESOLVED

    def test_partial_validation_a_succeeds_aaaa_fails(self):
        responses = {
            ("api.example.com", "A"): FakeAnswer("api.example.com", 300, [make_rdata("A", "1.2.3.4")]),
            ("api.example.com", "AAAA"): dns.exception.Timeout(),
        }

        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve_factory(responses)):
            status, records = validate_hostname("api.example.com", nameservers=None, timeout=1, lifetime=1)

        assert status == DnsValidationStatus.RESOLVED
        assert len(records) == 1
        assert records[0].type == "A"


class TestDetectWildcardIps:
    def test_no_wildcard(self):
        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve_factory({})):
            ips = detect_wildcard_ips("example.com", nameservers=None, timeout=1, lifetime=1)

        assert ips == set()

    def test_wildcard_detected(self):
        def fake_resolve(name, record_type, raise_on_no_answer=False):
            if record_type == "A":
                return FakeAnswer(str(name), 300, [make_rdata("A", "9.9.9.9")])
            return NoAnswerAnswer()

        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
            ips = detect_wildcard_ips("example.com", nameservers=None, timeout=1, lifetime=1)

        assert ips == {"9.9.9.9"}
