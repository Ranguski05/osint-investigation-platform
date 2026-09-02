"""
Cross-source integration tests for the expanded subdomain collector:
crt.sh + Cert Spotter + SecurityTrails + dns_bruteforce running together
through the real SubdomainCollector.

test_collector.py already exercises the collector's orchestration logic
in isolation using generic FakeSource instances (scope filtering,
dedup-with-provenance, bounding, status calculation). This file instead
proves that the four *real* source implementations -- each with its own
HTTP/DNS mocked independently -- compose correctly through that same
shared pipeline, and specifically covers the partial-failure scenario
described in the project's subdomain-enumerator expansion spec: one
source erroring, one succeeding, one failing auth, and one active source
succeeding, all landing in a single deduplicated result.
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import patch

from collectors.subdomains.collector import SubdomainCollector
from collectors.subdomains.models import (
    CollectionStatus,
    DnsValidationStatus,
    SourceStatus,
    SubdomainCollectorConfig,
)
from collectors.subdomains.sources.certspotter import CertSpotterSource
from collectors.subdomains.sources.crtsh import CrtShSource
from collectors.subdomains.sources.dns_bruteforce import DNSBruteforceSource
from collectors.subdomains.sources.securitytrails import SecurityTrailsSource


class FakeHttpResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def json_response(data) -> FakeHttpResponse:
    return FakeHttpResponse(json.dumps(data).encode("utf-8"))


def certspotter_issuance(issuance_id: str, dns_names: list[str]) -> dict:
    return {"id": issuance_id, "dns_names": dns_names}


def urlopen_router(responses_by_host: dict[str, object]):
    """
    Route urllib.request.urlopen() calls to a canned response/exception
    based on which host the request URL targets, so crt.sh, Cert Spotter,
    and SecurityTrails can each be mocked independently within one test
    even though all three go through the same patched function.
    """

    def fake_urlopen(request, timeout=None):
        for host, outcome in responses_by_host.items():
            if host in request.full_url:
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome
        raise AssertionError(f"Unexpected request to {request.full_url}")

    return fake_urlopen


class TestFourSourcePartialFailureScenario:
    """
    Mirrors the exact scenario from the expansion spec: crt.sh errors,
    Cert Spotter finds 14 names, SecurityTrails fails auth, dns_bruteforce
    finds 5 names -- overlapping where the spec implies they would --
    and the final collection must still surface all discovered
    subdomains with correct per-source accounting.
    """

    def test_partial_success_yields_all_surviving_discoveries(self):
        certspotter_names = [f"host{i}.example.com" for i in range(14)]
        bruteforce_words = ["w0", "w1", "w2", "w3", "w4"]

        responses = {
            "crt.sh": urllib.error.HTTPError("https://crt.sh/", 502, "Bad Gateway", {}, None),
            "api.certspotter.com": json_response([certspotter_issuance("1", certspotter_names)]),
            # SecurityTrailsSource raises AUTH_ERROR before any request when
            # no key is configured -- no canned response needed for it.
        }

        config = SubdomainCollectorConfig(request_timeout=5.0)
        sources = [
            CrtShSource(),
            CertSpotterSource(),
            SecurityTrailsSource(api_key=None),
            DNSBruteforceSource(bruteforce_words, detect_wildcard=False),
        ]
        collector = SubdomainCollector(config=config, sources=sources)

        with (
            patch("urllib.request.urlopen", side_effect=urlopen_router(responses)),
            patch("collectors.subdomains.sources.dns_bruteforce.validate_hostname") as mock_validate,
        ):
            mock_validate.side_effect = lambda hostname, **_: (DnsValidationStatus.RESOLVED, [])
            result = collector.collect("example.com")

        assert result.status == CollectionStatus.PARTIAL

        source_by_name = {s.source: s for s in result.sources}
        assert source_by_name["certificate_transparency"].status == SourceStatus.FAILED
        assert source_by_name["certificate_transparency"].error_type == "SOURCE_ERROR"
        assert source_by_name["certificate_transparency_certspotter"].status == SourceStatus.SUCCESS
        assert source_by_name["certificate_transparency_certspotter"].candidate_count == 14
        assert source_by_name["securitytrails"].status == SourceStatus.FAILED
        assert source_by_name["securitytrails"].error_type == "AUTH_ERROR"
        assert source_by_name["dns_bruteforce"].status == SourceStatus.SUCCESS
        assert source_by_name["dns_bruteforce"].candidate_count == 5

        # 14 (Cert Spotter) + 5 (bruteforce), none overlapping in this scenario.
        assert len(result.observations) == 19
        assert result.candidate_count == 19

        # Failures are preserved as structured errors, not silently dropped.
        error_types = {e.error_type for e in result.errors}
        assert error_types == {"SOURCE_ERROR", "AUTH_ERROR"}


class TestProvenanceMerging:
    def test_same_hostname_from_three_passive_sources_merges_with_full_provenance(self):
        shared_host = "api.example.com"

        responses = {
            "crt.sh": json_response([{"id": 1, "name_value": shared_host}]),
            "api.certspotter.com": json_response([certspotter_issuance("1", [shared_host])]),
        }

        collector = SubdomainCollector(
            sources=[
                CrtShSource(),
                CertSpotterSource(),
                SecurityTrailsSource(api_key="key"),
            ]
        )

        st_response = json_response({"subdomains": ["api"]})
        responses["api.securitytrails.com"] = st_response

        with patch("urllib.request.urlopen", side_effect=urlopen_router(responses)):
            result = collector.collect("example.com")

        assert result.status == CollectionStatus.SUCCESS
        assert len(result.observations) == 1

        discovered_sources = {e.source for e in result.observations[0].discovery}
        assert discovered_sources == {"certificate_transparency", "certificate_transparency_certspotter", "securitytrails"}


class TestSuccessfulEmptyVsFailedSource:
    def test_empty_success_and_hard_failure_are_distinguishable(self):
        responses = {
            "crt.sh": json_response([]),  # legitimate empty result
            "api.certspotter.com": urllib.error.URLError("connection refused"),
        }

        collector = SubdomainCollector(sources=[CrtShSource(), CertSpotterSource()])

        with patch("urllib.request.urlopen", side_effect=urlopen_router(responses)):
            result = collector.collect("example.com")

        source_by_name = {s.source: s for s in result.sources}
        assert source_by_name["certificate_transparency"].status == SourceStatus.SUCCESS
        assert source_by_name["certificate_transparency"].candidate_count == 0
        assert source_by_name["certificate_transparency_certspotter"].status == SourceStatus.FAILED
        assert source_by_name["certificate_transparency_certspotter"].error_type == "NETWORK_ERROR"
        assert result.status == CollectionStatus.PARTIAL


class TestAllSourcesFailing:
    def test_all_four_sources_failing_yields_failed_status_not_a_crash(self):
        responses = {
            "crt.sh": urllib.error.HTTPError("https://crt.sh/", 502, "Bad Gateway", {}, None),
            "api.certspotter.com": urllib.error.URLError("connection refused"),
        }

        collector = SubdomainCollector(
            sources=[
                CrtShSource(),
                CertSpotterSource(),
                SecurityTrailsSource(api_key=None),
            ]
        )

        with patch("urllib.request.urlopen", side_effect=urlopen_router(responses)):
            result = collector.collect("example.com")

        assert result.status == CollectionStatus.FAILED
        assert result.observations == []
        assert len(result.sources) == 3
        assert all(s.status == SourceStatus.FAILED for s in result.sources)


class TestResultBoundsAcrossSources:
    def test_max_candidates_bounds_the_merged_multi_source_result(self):
        certspotter_names = [f"host{i}.example.com" for i in range(50)]
        responses = {
            "crt.sh": json_response([{"id": 1, "name_value": "crtsh-only.example.com"}]),
            "api.certspotter.com": json_response([certspotter_issuance("1", certspotter_names)]),
        }

        collector = SubdomainCollector(
            config=SubdomainCollectorConfig(max_candidates=10),
            sources=[CrtShSource(), CertSpotterSource()],
        )

        with patch("urllib.request.urlopen", side_effect=urlopen_router(responses)):
            result = collector.collect("example.com")

        assert len(result.observations) == 10
        assert result.truncated is True
        assert result.candidate_count == 51
