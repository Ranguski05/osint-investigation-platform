"""
Tests for collectors/subdomains/sources/dns_bruteforce.py.

dns.resolver.Resolver.resolve is mocked at the class level -- same
approach as test_dns_validation.py, since dns_validation.py (which this
source calls into) builds its own Resolver instance internally. Nothing
here touches the network or the real filesystem.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor as RealThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from collectors.subdomains.models import SourceType
from collectors.subdomains.sources.base import RawCandidate
from collectors.subdomains.sources.dns_bruteforce import (
    DEFAULT_WORDLIST,
    DNSBruteforceSource,
    _prepare_words,
    parse_wordlist,
)


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


class TestWordlistParsing:
    def test_default_wordlist_loads(self):
        source = DNSBruteforceSource()
        assert source._raw_wordlist == DEFAULT_WORDLIST
        assert len(DEFAULT_WORDLIST) > 0

    def test_custom_wordlist_loads(self):
        words = parse_wordlist("api\nwww\n")
        assert words == ["api", "www"]

    def test_blank_lines_ignored(self):
        words = parse_wordlist("api\n\n\nwww\n")
        assert words == ["api", "www"]

    def test_whitespace_handled(self):
        words = parse_wordlist("  api  \n\twww\t\n")
        assert words == ["api", "www"]

    def test_duplicate_words_deduplicated(self):
        words = parse_wordlist("api\nAPI\napi\n")
        assert words == ["api"]

    def test_invalid_entries_are_dropped_not_raising(self):
        words = parse_wordlist("api\nadmin@example.com\n*.wild\nwww\n \n-leading-hyphen\n")
        assert words == ["api", "www"]

    def test_non_string_entries_are_skipped(self):
        assert _prepare_words(["api", 123, None, "www"]) == ["api", "www"]


class TestCandidateGeneration:
    def test_word_becomes_subdomain_candidate(self):
        with patch(
            "dns.resolver.Resolver.resolve",
            side_effect=fake_resolve_factory(
                {("api.example.com", "A"): FakeAnswer("api.example.com", 300, [make_rdata("A", "1.2.3.4")])}
            ),
        ):
            source = DNSBruteforceSource(["api"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert candidates == [RawCandidate(hostname="api.example.com", source_reference="api")]

    def test_uppercase_words_are_normalized(self):
        with patch(
            "dns.resolver.Resolver.resolve",
            side_effect=fake_resolve_factory(
                {("api.example.com", "A"): FakeAnswer("api.example.com", 300, [make_rdata("A", "1.2.3.4")])}
            ),
        ):
            source = DNSBruteforceSource(["API"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert candidates[0].hostname == "api.example.com"

    def test_candidates_are_always_in_scope_of_the_domain(self):
        with patch(
            "dns.resolver.Resolver.resolve",
            side_effect=fake_resolve_factory(
                {
                    ("api.example.com", "A"): FakeAnswer("api.example.com", 300, [make_rdata("A", "1.2.3.4")]),
                    ("www.example.com", "A"): FakeAnswer("www.example.com", 300, [make_rdata("A", "1.2.3.4")]),
                }
            ),
        ):
            source = DNSBruteforceSource(["api", "www"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert all(c.hostname.endswith(".example.com") for c in candidates)

    def test_no_candidates_when_wordlist_is_empty_after_normalization(self):
        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve_factory({})):
            source = DNSBruteforceSource(["*", "@@", ""], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert candidates == []


class TestDnsValidationOutcomes:
    def test_a_record_is_discovered(self):
        with patch(
            "dns.resolver.Resolver.resolve",
            side_effect=fake_resolve_factory(
                {("api.example.com", "A"): FakeAnswer("api.example.com", 300, [make_rdata("A", "1.2.3.4")])}
            ),
        ):
            source = DNSBruteforceSource(["api"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert len(candidates) == 1

    def test_aaaa_record_is_discovered(self):
        with patch(
            "dns.resolver.Resolver.resolve",
            side_effect=fake_resolve_factory(
                {
                    ("api.example.com", "AAAA"): FakeAnswer(
                        "api.example.com", 300, [make_rdata("AAAA", "2606:2800:220:1:248:1893:25c8:1946")]
                    )
                }
            ),
        ):
            source = DNSBruteforceSource(["api"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert len(candidates) == 1

    def test_cname_record_is_discovered(self):
        with patch(
            "dns.resolver.Resolver.resolve",
            side_effect=fake_resolve_factory(
                {("www.example.com", "CNAME"): FakeAnswer("www.example.com", 300, [make_rdata("CNAME", "example.com.")])}
            ),
        ):
            source = DNSBruteforceSource(["www"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert len(candidates) == 1

    def test_nxdomain_is_not_discovered(self):
        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve_factory({})):
            source = DNSBruteforceSource(["nonexistent"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert candidates == []

    def test_timeout_is_handled_as_not_discovered(self):
        with patch("dns.resolver.Resolver.resolve", side_effect=dns.exception.Timeout()):
            source = DNSBruteforceSource(["slow"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert candidates == []

    def test_servfail_is_handled_as_not_discovered(self):
        fake_request = SimpleNamespace(question=["example.com IN A"])
        exc = dns.resolver.NoNameservers(request=fake_request, errors=[("8.8.8.8", False, 53, Exception("SERVFAIL"), None)])

        with patch("dns.resolver.Resolver.resolve", side_effect=exc):
            source = DNSBruteforceSource(["broken"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert candidates == []

    def test_network_error_on_one_candidate_does_not_abort_others(self):
        def fake_resolve(name, record_type, raise_on_no_answer=False):
            if "bad" in str(name):
                raise OSError("network unreachable")
            if str(name).rstrip(".") == "good.example.com" and record_type == "A":
                return FakeAnswer("good.example.com", 300, [make_rdata("A", "1.2.3.4")])
            return NoAnswerAnswer()

        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
            source = DNSBruteforceSource(["bad", "good"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert [c.hostname for c in candidates] == ["good.example.com"]

    def test_unexpected_exception_from_future_does_not_abort_enumeration(self):
        def fake_resolve(name, record_type, raise_on_no_answer=False):
            if "boom" in str(name):
                raise RuntimeError("unexpected bug")
            if str(name).rstrip(".") == "ok.example.com" and record_type == "A":
                return FakeAnswer("ok.example.com", 300, [make_rdata("A", "1.2.3.4")])
            return NoAnswerAnswer()

        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
            source = DNSBruteforceSource(["boom", "ok"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)  # must not raise

        assert [c.hostname for c in candidates] == ["ok.example.com"]


class TestWildcardHandling:
    def test_wildcard_only_match_is_suppressed(self):
        def fake_resolve(name, record_type, raise_on_no_answer=False):
            # Every A query -- including the random wildcard probe --
            # resolves to the same IP, simulating wildcard DNS.
            if record_type == "A":
                return FakeAnswer(str(name), 300, [make_rdata("A", "9.9.9.9")])
            return NoAnswerAnswer()

        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
            source = DNSBruteforceSource(["random123"], detect_wildcard=True)
            candidates = source.enumerate("example.com", timeout=1)

        assert candidates == []

    def test_wildcard_detection_disabled_lets_candidate_through(self):
        def fake_resolve(name, record_type, raise_on_no_answer=False):
            if record_type == "A":
                return FakeAnswer(str(name), 300, [make_rdata("A", "9.9.9.9")])
            return NoAnswerAnswer()

        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
            source = DNSBruteforceSource(["api"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert len(candidates) == 1

    def test_no_wildcard_does_not_suppress_genuine_matches(self):
        def fake_resolve(name, record_type, raise_on_no_answer=False):
            # Wildcard probe (random uuid-based hostname) never resolves;
            # the real candidate does, at a distinct IP.
            if record_type == "A" and str(name).rstrip(".") == "api.example.com":
                return FakeAnswer("api.example.com", 300, [make_rdata("A", "1.2.3.4")])
            return NoAnswerAnswer()

        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
            source = DNSBruteforceSource(["api"], detect_wildcard=True)
            candidates = source.enumerate("example.com", timeout=1)

        assert len(candidates) == 1

    def test_wildcard_does_not_invent_candidates_beyond_the_wordlist(self):
        def fake_resolve(name, record_type, raise_on_no_answer=False):
            if record_type == "A":
                return FakeAnswer(str(name), 300, [make_rdata("A", "9.9.9.9")])
            return NoAnswerAnswer()

        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
            source = DNSBruteforceSource(["api", "www"], detect_wildcard=True)
            candidates = source.enumerate("example.com", timeout=1)

        # Wildcard suppressed both real wordlist candidates -- and no
        # candidate outside the two-word wordlist was ever generated.
        assert candidates == []


class TestLimits:
    def test_max_words_is_respected(self):
        source = DNSBruteforceSource([f"w{i}" for i in range(10)], max_words=3, detect_wildcard=False)
        queried = _record_queried_hostnames(source, "example.com")

        assert len(queried) == 3

    def test_large_wordlist_truncated_deterministically(self):
        words = [f"w{i}" for i in range(50)]

        source_a = DNSBruteforceSource(words, max_words=5, detect_wildcard=False)
        queried_a = _record_queried_hostnames(source_a, "example.com")

        source_b = DNSBruteforceSource(words, max_words=5, detect_wildcard=False)
        queried_b = _record_queried_hostnames(source_b, "example.com")

        assert queried_a == queried_b
        assert len(queried_a) == 5

    def test_rejects_non_positive_concurrency(self):
        with pytest.raises(ValueError):
            DNSBruteforceSource(["api"], concurrency=0)

    def test_rejects_non_positive_max_words(self):
        with pytest.raises(ValueError):
            DNSBruteforceSource(["api"], max_words=0)

    def test_concurrency_is_passed_to_the_thread_pool(self):
        with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve_factory({})):
            with patch(
                "collectors.subdomains.sources.dns_bruteforce.ThreadPoolExecutor",
                wraps=RealThreadPoolExecutor,
            ) as mock_pool:
                source = DNSBruteforceSource(["api"], concurrency=2, detect_wildcard=False)
                source.enumerate("example.com", timeout=1)

        mock_pool.assert_called_once_with(max_workers=2)


def _record_queried_hostnames(source: DNSBruteforceSource, domain: str) -> list[str]:
    """Run enumerate() with every DNS query recorded (and unresolved), returning the distinct hostnames queried."""

    queried: set[str] = set()

    def fake_resolve(name, record_type, raise_on_no_answer=False):
        queried.add(str(name).rstrip("."))
        return NoAnswerAnswer()

    with patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
        source.enumerate(domain, timeout=1)

    return sorted(queried)


class TestProvenance:
    def test_source_identity(self):
        assert DNSBruteforceSource.name == "dns_bruteforce"
        assert DNSBruteforceSource.method == "wordlist"
        assert DNSBruteforceSource.source_type == SourceType.ACTIVE

    def test_source_reference_preserves_the_tested_word(self):
        with patch(
            "dns.resolver.Resolver.resolve",
            side_effect=fake_resolve_factory(
                {("api.example.com", "A"): FakeAnswer("api.example.com", 300, [make_rdata("A", "1.2.3.4")])}
            ),
        ):
            source = DNSBruteforceSource(["api"], detect_wildcard=False)
            candidates = source.enumerate("example.com", timeout=1)

        assert candidates[0].source_reference == "api"
