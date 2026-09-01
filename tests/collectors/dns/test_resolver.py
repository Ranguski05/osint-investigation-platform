"""
Tests for collectors/dns/resolver.py.

These are deterministic unit tests: `dns.resolver.Resolver.resolve` is
mocked so nothing here touches the network or the public internet. Rdata
objects are still *real* dnspython objects (built via `dns.rdata.from_text`)
so record normalization is exercised against the library's actual parsing,
not a hand-rolled stand-in.
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
import pytest

from collectors.dns.models import QueryStatus
from collectors.dns.resolver import DNSResolver


def make_rdata(record_type: str, text: str):
    """Build a real dnspython rdata object from its zone-file text form."""

    return dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.from_text(record_type),
        text,
    )


class FakeAnswer:
    """
    Minimal stand-in for dns.resolver.Answer -- just enough surface area
    for DNSResolver._normalize_answer (`.name`, `.rrset.ttl`, iteration).
    """

    def __init__(self, name: str, ttl: int, rdata_list: list):
        self.name = dns.name.from_text(name)
        self.rrset = SimpleNamespace(ttl=ttl)
        self._rdata_list = rdata_list

    def __iter__(self):
        return iter(self._rdata_list)


class NoAnswerAnswer:
    """Stand-in for an Answer with no rrset (NODATA response)."""

    rrset = None


@pytest.fixture
def resolver() -> DNSResolver:
    return DNSResolver(nameservers=["8.8.8.8"], timeout=1, lifetime=1)


class TestQuerySuccess:
    def test_a_record(self, resolver: DNSResolver):
        answer = FakeAnswer("example.com", 300, [make_rdata("A", "93.184.216.34")])

        with patch.object(resolver.resolver, "resolve", return_value=answer):
            result = resolver.query("example.com", "A")

        assert result.status == QueryStatus.SUCCESS
        assert result.error_type is None
        assert len(result.records) == 1
        record = result.records[0]
        assert record.type == "A"
        assert record.name == "example.com"
        assert record.value == "93.184.216.34"
        assert record.ttl == 300
        assert result.duration_ms >= 0

    def test_aaaa_record(self, resolver: DNSResolver):
        answer = FakeAnswer("example.com", 300, [make_rdata("AAAA", "2606:2800:220:1:248:1893:25c8:1946")])

        with patch.object(resolver.resolver, "resolve", return_value=answer):
            result = resolver.query("example.com", "AAAA")

        assert result.records[0].value == "2606:2800:220:1:248:1893:25c8:1946"

    def test_cname_record(self, resolver: DNSResolver):
        answer = FakeAnswer("www.example.com", 300, [make_rdata("CNAME", "example.com.")])

        with patch.object(resolver.resolver, "resolve", return_value=answer):
            result = resolver.query("www.example.com", "CNAME")

        assert result.records[0].value == "example.com"

    def test_mx_record_preserves_priority(self, resolver: DNSResolver):
        answer = FakeAnswer("example.com", 300, [make_rdata("MX", "10 mail.example.com.")])

        with patch.object(resolver.resolver, "resolve", return_value=answer):
            result = resolver.query("example.com", "MX")

        record = result.records[0]
        assert record.value == "mail.example.com"
        assert record.attributes["priority"] == 10

    def test_multiple_mx_records_with_different_priorities(self, resolver: DNSResolver):
        answer = FakeAnswer(
            "example.com",
            300,
            [
                make_rdata("MX", "10 mail1.example.com."),
                make_rdata("MX", "20 mail2.example.com."),
            ],
        )

        with patch.object(resolver.resolver, "resolve", return_value=answer):
            result = resolver.query("example.com", "MX")

        priorities = {record.value: record.attributes["priority"] for record in result.records}
        assert priorities == {"mail1.example.com": 10, "mail2.example.com": 20}

    def test_ns_record(self, resolver: DNSResolver):
        answer = FakeAnswer("example.com", 21600, [make_rdata("NS", "ns1.example.com.")])

        with patch.object(resolver.resolver, "resolve", return_value=answer):
            result = resolver.query("example.com", "NS")

        assert result.records[0].value == "ns1.example.com"

    def test_txt_record(self, resolver: DNSResolver):
        answer = FakeAnswer("example.com", 300, [make_rdata("TXT", '"v=spf1 -all"')])

        with patch.object(resolver.resolver, "resolve", return_value=answer):
            result = resolver.query("example.com", "TXT")

        assert result.records[0].value == '"v=spf1 -all"'

    def test_soa_record_preserves_all_fields(self, resolver: DNSResolver):
        answer = FakeAnswer(
            "example.com",
            3600,
            [make_rdata("SOA", "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600")],
        )

        with patch.object(resolver.resolver, "resolve", return_value=answer):
            result = resolver.query("example.com", "SOA")

        record = result.records[0]
        assert record.value == "ns1.example.com"
        assert record.attributes["rname"] == "hostmaster.example.com"
        assert record.attributes["serial"] == 2024010101
        assert record.attributes["refresh"] == 7200
        assert record.attributes["retry"] == 3600
        assert record.attributes["expire"] == 1209600
        assert record.attributes["minimum"] == 3600

    def test_caa_record_decodes_bytes_fields(self, resolver: DNSResolver):
        # Regression test: dnspython returns CAA tag/value as raw bytes,
        # which must be decoded to str before this ever reaches JSON.
        answer = FakeAnswer("example.com", 300, [make_rdata("CAA", '0 issue "letsencrypt.org"')])

        with patch.object(resolver.resolver, "resolve", return_value=answer):
            result = resolver.query("example.com", "CAA")

        record = result.records[0]
        assert isinstance(record.attributes["tag"], str)
        assert isinstance(record.attributes["value"], str)
        assert record.attributes["tag"] == "issue"
        assert record.attributes["value"] == "letsencrypt.org"

    def test_ptr_record(self, resolver: DNSResolver):
        answer = FakeAnswer("34.216.184.93.in-addr.arpa", 300, [make_rdata("PTR", "example.com.")])

        with patch.object(resolver.resolver, "resolve", return_value=answer):
            result = resolver.query("34.216.184.93.in-addr.arpa", "PTR")

        assert result.records[0].value == "example.com"

    def test_dnskey_record(self, resolver: DNSResolver):
        answer = FakeAnswer(
            "example.com",
            3600,
            [make_rdata("DNSKEY", "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbz")],
        )

        with patch.object(resolver.resolver, "resolve", return_value=answer):
            result = resolver.query("example.com", "DNSKEY")

        record = result.records[0]
        assert record.attributes["flags"] == 257
        assert record.attributes["protocol"] == 3
        assert record.attributes["algorithm"] == 8

    def test_ds_record_hex_encodes_digest(self, resolver: DNSResolver):
        answer = FakeAnswer(
            "example.com",
            3600,
            [make_rdata("DS", "31589 8 2 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE9FDCF6" "343BA27B18F3DD9BAA")],
        )

        with patch.object(resolver.resolver, "resolve", return_value=answer):
            result = resolver.query("example.com", "DS")

        record = result.records[0]
        assert record.attributes["key_tag"] == 31589
        assert isinstance(record.attributes["digest"], str)


class TestQueryNoAnswer:
    def test_missing_rrset_is_no_answer(self, resolver: DNSResolver):
        with patch.object(resolver.resolver, "resolve", return_value=NoAnswerAnswer()):
            result = resolver.query("example.com", "AAAA")

        assert result.status == QueryStatus.NO_ANSWER
        assert result.records == []

    def test_no_answer_exception(self, resolver: DNSResolver):
        with patch.object(resolver.resolver, "resolve", side_effect=dns.resolver.NoAnswer()):
            result = resolver.query("example.com", "MX")

        assert result.status == QueryStatus.NO_ANSWER
        assert result.error_type == "NO_ANSWER"


class TestQueryErrors:
    def test_nxdomain(self, resolver: DNSResolver):
        with patch.object(resolver.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = resolver.query("does-not-exist.invalid", "A")

        assert result.status == QueryStatus.NXDOMAIN
        assert result.error_type == "NXDOMAIN"
        assert result.records == []

    def test_lifetime_timeout(self, resolver: DNSResolver):
        with patch.object(resolver.resolver, "resolve", side_effect=dns.resolver.LifetimeTimeout()):
            result = resolver.query("example.com", "A")

        assert result.status == QueryStatus.TIMEOUT
        assert result.error_type == "TIMEOUT"

    def test_generic_dns_timeout(self, resolver: DNSResolver):
        with patch.object(resolver.resolver, "resolve", side_effect=dns.exception.Timeout()):
            result = resolver.query("example.com", "A")

        assert result.status == QueryStatus.TIMEOUT
        assert result.error_type == "TIMEOUT"

    def test_servfail(self, resolver: DNSResolver):
        fake_request = SimpleNamespace(question=["example.com IN A"])
        exc = dns.resolver.NoNameservers(
            request=fake_request,
            errors=[("8.8.8.8", False, 53, Exception("SERVFAIL"), None)],
        )

        with patch.object(resolver.resolver, "resolve", side_effect=exc):
            result = resolver.query("example.com", "A")

        assert result.status == QueryStatus.SERVFAIL
        assert result.error_type == "SERVFAIL"

    def test_refused(self, resolver: DNSResolver):
        fake_request = SimpleNamespace(question=["example.com IN A"])
        exc = dns.resolver.NoNameservers(
            request=fake_request,
            errors=[("8.8.8.8", False, 53, Exception("REFUSED"), None)],
        )

        with patch.object(resolver.resolver, "resolve", side_effect=exc):
            result = resolver.query("example.com", "A")

        assert result.status == QueryStatus.REFUSED
        assert result.error_type == "REFUSED"

    def test_network_error(self, resolver: DNSResolver):
        with patch.object(resolver.resolver, "resolve", side_effect=OSError("network unreachable")):
            result = resolver.query("example.com", "A")

        assert result.status == QueryStatus.ERROR
        assert result.error_type == "NETWORK_ERROR"

    def test_result_never_raises_to_caller(self, resolver: DNSResolver):
        # No matter what dnspython throws, query() must return a
        # QueryResult -- never propagate the exception.
        with patch.object(resolver.resolver, "resolve", side_effect=dns.exception.DNSException("boom")):
            result = resolver.query("example.com", "A")

        assert result.status == QueryStatus.ERROR
        assert result.error_type == "DNS_ERROR"


class TestReverseLookup:
    def test_invalid_ip_does_not_call_resolve(self, resolver: DNSResolver):
        with patch.object(resolver.resolver, "resolve") as mock_resolve:
            result = resolver.reverse_lookup("not-an-ip")

        mock_resolve.assert_not_called()
        assert result.status == QueryStatus.ERROR
        assert result.error_type == "INVALID_IP"

    def test_valid_ipv4_queries_ptr(self, resolver: DNSResolver):
        answer = FakeAnswer("34.216.184.93.in-addr.arpa", 300, [make_rdata("PTR", "example.com.")])

        with patch.object(resolver.resolver, "resolve", return_value=answer) as mock_resolve:
            result = resolver.reverse_lookup("93.184.216.34")

        assert mock_resolve.call_args.args[1] == "PTR"
        assert result.records[0].value == "example.com"


class TestResolverDescription:
    def test_reflects_configured_nameserver(self):
        resolver = DNSResolver(nameservers=["1.1.1.1"], timeout=1, lifetime=1)
        assert resolver.resolver_description == "1.1.1.1"

    def test_reflects_multiple_nameservers(self):
        resolver = DNSResolver(nameservers=["1.1.1.1", "8.8.8.8"], timeout=1, lifetime=1)
        assert resolver.resolver_description == "1.1.1.1,8.8.8.8"


class TestResolverValidation:
    def test_rejects_zero_timeout(self):
        with pytest.raises(ValueError):
            DNSResolver(timeout=0)

    def test_rejects_negative_lifetime(self):
        with pytest.raises(ValueError):
            DNSResolver(lifetime=-1)
