"""
Tests for collectors/subdomains/collector.py.

Sources are replaced with small in-test fakes (implementing
SubdomainSource directly) rather than mocking HTTP, so these exercise the
orchestration logic -- scope filtering, deduplication, bounding, source
failure handling, DNS validation opt-in, relationship generation -- in
isolation from crt.sh-specific parsing (covered in test_sources_crtsh.py).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from collectors.subdomains.collector import SubdomainCollector
from collectors.subdomains.exceptions import SourceError
from collectors.subdomains.models import (
    CollectionStatus,
    DnsValidationStatus,
    ResolvedRecord,
    SourceStatus,
    SourceType,
    SubdomainCollectorConfig,
)
from collectors.subdomains.sources.base import RawCandidate, SubdomainSource
from collectors.subdomains.sources.crtsh import CrtShSource
from collectors.subdomains.sources.dns_bruteforce import DNSBruteforceSource


class FakeSource(SubdomainSource):
    def __init__(
        self,
        name: str,
        method: str,
        candidates: list[RawCandidate] | None = None,
        error: Exception | None = None,
        source_type: SourceType = SourceType.PASSIVE,
    ):
        self.name = name
        self.method = method
        self._candidates = candidates or []
        self._error = error
        self.source_type = source_type
        self.calls: list[str] = []

    def enumerate(self, domain: str, *, timeout: float) -> list[RawCandidate]:
        self.calls.append(domain)
        if self._error is not None:
            raise self._error
        return self._candidates


class TestInputValidation:
    def test_malformed_target_returns_failed_collection_not_an_exception(self):
        collector = SubdomainCollector(sources=[FakeSource("s", "m")])

        result = collector.collect("not a valid host!!")

        assert result.status == CollectionStatus.FAILED
        assert result.errors[0].error_type == "INVALID_TARGET"

    def test_ip_target_is_rejected(self):
        collector = SubdomainCollector(sources=[FakeSource("s", "m")])

        result = collector.collect("93.184.216.34")

        assert result.status == CollectionStatus.FAILED

    def test_empty_target_is_rejected(self):
        collector = SubdomainCollector(sources=[FakeSource("s", "m")])

        result = collector.collect("")

        assert result.status == CollectionStatus.FAILED


class TestDiscoveryAndScope:
    def test_in_scope_candidates_become_observations(self):
        source = FakeSource(
            "certificate_transparency",
            "crtsh",
            [RawCandidate("api.example.com"), RawCandidate("www.example.com")],
        )
        collector = SubdomainCollector(sources=[source])

        result = collector.collect("example.com")

        assert {o.hostname for o in result.observations} == {"api.example.com", "www.example.com"}

    def test_out_of_scope_candidates_are_dropped_not_included(self):
        source = FakeSource(
            "s",
            "m",
            [
                RawCandidate("api.example.com"),
                RawCandidate("example.com.attacker.com"),
                RawCandidate("attackerexample.com"),
                RawCandidate("example.org"),
            ],
        )
        collector = SubdomainCollector(sources=[source])

        result = collector.collect("example.com")

        assert {o.hostname for o in result.observations} == {"api.example.com"}

    def test_wildcard_prefix_is_normalized(self):
        source = FakeSource("s", "m", [RawCandidate("*.api.example.com")])
        collector = SubdomainCollector(sources=[source])

        result = collector.collect("example.com")

        assert result.observations[0].hostname == "api.example.com"

    def test_root_domain_itself_is_a_valid_candidate(self):
        source = FakeSource("s", "m", [RawCandidate("example.com")])
        collector = SubdomainCollector(sources=[source])

        result = collector.collect("example.com")

        assert result.observations[0].hostname == "example.com"

    def test_unnormalizable_candidate_is_skipped_not_crashing(self):
        source = FakeSource("s", "m", [RawCandidate("admin@example.com"), RawCandidate("api.example.com")])
        collector = SubdomainCollector(sources=[source])

        result = collector.collect("example.com")

        assert len(result.observations) == 1
        assert result.observations[0].hostname == "api.example.com"


class TestDeduplication:
    def test_duplicate_hostname_different_casing_merges_into_one_observation(self):
        source = FakeSource("s", "m", [RawCandidate("api.example.com"), RawCandidate("API.example.com.")])
        collector = SubdomainCollector(sources=[source])

        result = collector.collect("example.com")

        assert len(result.observations) == 1
        assert len(result.observations[0].discovery) == 2

    def test_wildcard_and_concrete_hostname_merge(self):
        source = FakeSource("s", "m", [RawCandidate("*.api.example.com"), RawCandidate("api.example.com")])
        collector = SubdomainCollector(sources=[source])

        result = collector.collect("example.com")

        assert len(result.observations) == 1

    def test_same_hostname_from_two_sources_preserves_both(self):
        source_a = FakeSource("source_a", "method_a", [RawCandidate("api.example.com")])
        source_b = FakeSource("source_b", "method_b", [RawCandidate("api.example.com")])
        collector = SubdomainCollector(sources=[source_a, source_b])

        result = collector.collect("example.com")

        assert len(result.observations) == 1
        assert {e.source for e in result.observations[0].discovery} == {"source_a", "source_b"}


class TestLimits:
    def test_max_candidates_truncates(self):
        candidates = [RawCandidate(f"h{i}.example.com") for i in range(10)]
        collector = SubdomainCollector(
            config=SubdomainCollectorConfig(max_candidates=3),
            sources=[FakeSource("s", "m", candidates)],
        )

        result = collector.collect("example.com")

        assert len(result.observations) == 3
        assert result.truncated is True
        assert result.candidate_count == 10

    def test_truncation_is_deterministic_across_runs(self):
        candidates = [RawCandidate(f"h{i}.example.com") for i in range(10)]
        collector = SubdomainCollector(
            config=SubdomainCollectorConfig(max_candidates=3),
            sources=[FakeSource("s", "m", candidates)],
        )

        first = [o.hostname for o in collector.collect("example.com").observations]
        second = [o.hostname for o in collector.collect("example.com").observations]

        assert first == second

    def test_under_limit_is_not_truncated(self):
        collector = SubdomainCollector(
            config=SubdomainCollectorConfig(max_candidates=200),
            sources=[FakeSource("s", "m", [RawCandidate("api.example.com")])],
        )

        result = collector.collect("example.com")

        assert result.truncated is False

    def test_rejects_non_positive_max_candidates(self):
        with pytest.raises(ValueError):
            SubdomainCollector(config=SubdomainCollectorConfig(max_candidates=0))


class TestSourceFailureHandling:
    def test_one_source_fails_other_succeeds_yields_partial(self):
        good = FakeSource("good", "m", [RawCandidate("api.example.com")])
        bad = FakeSource("bad", "m", error=SourceError("timed out"))
        collector = SubdomainCollector(sources=[good, bad])

        result = collector.collect("example.com")

        assert result.status == CollectionStatus.PARTIAL
        assert len(result.observations) == 1
        assert any(s.status == SourceStatus.FAILED for s in result.sources)
        assert any(e.error_type == "SOURCE_ERROR" for e in result.errors)

    def test_all_sources_failing_yields_failed(self):
        bad = FakeSource("bad", "m", error=SourceError("boom"))
        collector = SubdomainCollector(sources=[bad])

        result = collector.collect("example.com")

        assert result.status == CollectionStatus.FAILED
        assert result.observations == []

    def test_unexpected_exception_in_a_source_does_not_crash_the_collection(self):
        class ExplodingSource(SubdomainSource):
            name = "exploding"
            method = "boom"
            source_type = SourceType.PASSIVE

            def enumerate(self, domain: str, *, timeout: float) -> list[RawCandidate]:
                raise RuntimeError("bug in a hypothetical source")

        collector = SubdomainCollector(sources=[ExplodingSource()])

        result = collector.collect("example.com")  # must not raise

        assert result.status == CollectionStatus.FAILED
        assert result.sources[0].error_type == "UNEXPECTED_ERROR"

    def test_all_sources_succeeding_yields_success(self):
        collector = SubdomainCollector(sources=[FakeSource("s", "m", [RawCandidate("api.example.com")])])

        result = collector.collect("example.com")

        assert result.status == CollectionStatus.SUCCESS

    def test_source_errors_default_error_type_is_source_error(self):
        # Unchanged behavior for sources that don't set a custom
        # error_type (e.g. crt.sh, dns_bruteforce) -- see exceptions.SourceError.
        bad = FakeSource("bad", "m", error=SourceError("boom"))
        collector = SubdomainCollector(sources=[bad])

        result = collector.collect("example.com")

        assert result.sources[0].error_type == "SOURCE_ERROR"
        assert result.errors[0].error_type == "SOURCE_ERROR"

    def test_source_error_custom_error_type_propagates_to_source_result_and_error(self):
        bad = FakeSource("securitytrails", "m", error=SourceError("no api key", error_type="AUTH_ERROR"))
        collector = SubdomainCollector(sources=[bad])

        result = collector.collect("example.com")

        assert result.sources[0].error_type == "AUTH_ERROR"
        assert result.errors[0].error_type == "AUTH_ERROR"
        assert result.errors[0].message == "no api key"


class TestDnsValidationOptIn:
    def test_disabled_by_default(self):
        collector = SubdomainCollector(sources=[FakeSource("s", "m", [RawCandidate("api.example.com")])])

        result = collector.collect("example.com")

        assert result.observations[0].dns_status == DnsValidationStatus.NOT_CHECKED
        assert result.observations[0].dns_records == []

    def test_enabled_resolves_each_observation(self):
        collector = SubdomainCollector(
            config=SubdomainCollectorConfig(validate_dns=True, detect_wildcard=False),
            sources=[FakeSource("s", "m", [RawCandidate("api.example.com")])],
        )

        with patch(
            "collectors.subdomains.collector.validate_hostname",
            return_value=(DnsValidationStatus.RESOLVED, [ResolvedRecord(type="A", value="1.2.3.4", ttl=300)]),
        ) as mock_validate:
            result = collector.collect("example.com")

        mock_validate.assert_called_once()
        assert result.observations[0].dns_status == DnsValidationStatus.RESOLVED
        assert result.observations[0].dns_records[0].value == "1.2.3.4"

    def test_validation_bounded_by_max_candidates(self):
        candidates = [RawCandidate(f"h{i}.example.com") for i in range(10)]
        collector = SubdomainCollector(
            config=SubdomainCollectorConfig(validate_dns=True, detect_wildcard=False, max_candidates=3),
            sources=[FakeSource("s", "m", candidates)],
        )

        with patch(
            "collectors.subdomains.collector.validate_hostname",
            return_value=(DnsValidationStatus.UNRESOLVED, []),
        ) as mock_validate:
            collector.collect("example.com")

        assert mock_validate.call_count == 3

    def test_wildcard_matching_candidate_is_flagged(self):
        collector = SubdomainCollector(
            config=SubdomainCollectorConfig(validate_dns=True, detect_wildcard=True),
            sources=[FakeSource("s", "m", [RawCandidate("random123.example.com")])],
        )

        with (
            patch("collectors.subdomains.collector.detect_wildcard_ips", return_value={"9.9.9.9"}),
            patch(
                "collectors.subdomains.collector.validate_hostname",
                return_value=(DnsValidationStatus.RESOLVED, [ResolvedRecord(type="A", value="9.9.9.9", ttl=300)]),
            ),
        ):
            result = collector.collect("example.com")

        assert result.observations[0].is_wildcard_match is True

    def test_non_wildcard_candidate_is_not_flagged(self):
        collector = SubdomainCollector(
            config=SubdomainCollectorConfig(validate_dns=True, detect_wildcard=True),
            sources=[FakeSource("s", "m", [RawCandidate("api.example.com")])],
        )

        with (
            patch("collectors.subdomains.collector.detect_wildcard_ips", return_value=set()),
            patch(
                "collectors.subdomains.collector.validate_hostname",
                return_value=(DnsValidationStatus.RESOLVED, [ResolvedRecord(type="A", value="1.2.3.4", ttl=300)]),
            ),
        ):
            result = collector.collect("example.com")

        assert result.observations[0].is_wildcard_match is False


class TestRelationshipGeneration:
    def test_discovered_subdomain_relationship_is_created(self):
        collector = SubdomainCollector(
            sources=[FakeSource("certificate_transparency", "crtsh", [RawCandidate("api.example.com")])]
        )

        result = collector.collect("example.com")

        rel = result.related_entities[0]
        assert rel.entity_type == "hostname"
        assert rel.value == "api.example.com"
        assert rel.relationship == "discovered_subdomain"
        assert rel.source_record == "certificate_transparency"

    def test_one_relationship_per_observation_not_per_evidence(self):
        source_a = FakeSource("source_a", "m", [RawCandidate("api.example.com")])
        source_b = FakeSource("source_b", "m", [RawCandidate("api.example.com")])
        collector = SubdomainCollector(sources=[source_a, source_b])

        result = collector.collect("example.com")

        assert len(result.related_entities) == 1


class TestVersioning:
    def test_collector_info(self):
        collector = SubdomainCollector(sources=[FakeSource("s", "m", [])])

        result = collector.collect("example.com")

        assert result.collector.name == "subdomains"
        assert result.collector.version == SubdomainCollector.VERSION


class TestSourceTypePropagation:
    def test_source_type_recorded_on_success(self):
        passive = FakeSource("passive_src", "m", [], source_type=SourceType.PASSIVE)
        active = FakeSource("active_src", "m", [], source_type=SourceType.ACTIVE)
        collector = SubdomainCollector(sources=[passive, active])

        result = collector.collect("example.com")

        types = {s.source: s.source_type for s in result.sources}
        assert types == {"passive_src": SourceType.PASSIVE, "active_src": SourceType.ACTIVE}

    def test_source_type_recorded_on_failure(self):
        active = FakeSource("active_src", "m", error=SourceError("boom"), source_type=SourceType.ACTIVE)
        collector = SubdomainCollector(sources=[active])

        result = collector.collect("example.com")

        assert result.sources[0].source_type == SourceType.ACTIVE

    def test_real_sources_declare_expected_types(self):
        assert CrtShSource.source_type == SourceType.PASSIVE
        assert DNSBruteforceSource.source_type == SourceType.ACTIVE


class TestMultiSourceIntegrationWithBruteforce:
    """
    Exercises certificate_transparency + dns_bruteforce running together
    through the real collector -- the passive source is a FakeSource
    (no HTTP), the active source is the real DNSBruteforceSource with
    DNS mocked, proving the two independent sources merge correctly
    through the one shared pipeline.
    """

    def test_same_hostname_from_ct_and_bruteforce_merges_into_one_observation(self):
        ct_source = FakeSource(
            "certificate_transparency", "crtsh", [RawCandidate("api.example.com", source_reference="1")]
        )
        bruteforce_source = FakeSource(
            "dns_bruteforce", "wordlist", [RawCandidate("api.example.com", source_reference="api")],
            source_type=SourceType.ACTIVE,
        )
        collector = SubdomainCollector(sources=[ct_source, bruteforce_source])

        result = collector.collect("example.com")

        assert len(result.observations) == 1
        assert {e.source for e in result.observations[0].discovery} == {"certificate_transparency", "dns_bruteforce"}

    def test_bruteforce_only_discovery_becomes_an_observation_and_relationship(self):
        with patch("collectors.subdomains.sources.dns_bruteforce.detect_wildcard_ips", return_value=set()), patch(
            "collectors.subdomains.sources.dns_bruteforce.validate_hostname",
            return_value=(DnsValidationStatus.RESOLVED, [ResolvedRecord(type="A", value="1.2.3.4", ttl=300)]),
        ):
            bruteforce_source = DNSBruteforceSource(["api"], detect_wildcard=True)
            collector = SubdomainCollector(sources=[bruteforce_source])

            result = collector.collect("example.com")

        assert result.status == CollectionStatus.SUCCESS
        assert result.observations[0].hostname == "api.example.com"
        assert result.observations[0].discovery[0].source == "dns_bruteforce"
        assert result.observations[0].discovery[0].source_reference == "api"
        assert result.related_entities[0].relationship == "discovered_subdomain"
        assert result.sources[0].source_type == SourceType.ACTIVE

    def test_bruteforce_failure_does_not_prevent_ct_discoveries(self):
        ct_source = FakeSource("certificate_transparency", "crtsh", [RawCandidate("www.example.com")])
        broken_bruteforce = FakeSource(
            "dns_bruteforce", "wordlist", error=SourceError("resolver unavailable"), source_type=SourceType.ACTIVE
        )
        collector = SubdomainCollector(sources=[ct_source, broken_bruteforce])

        result = collector.collect("example.com")

        assert result.status == CollectionStatus.PARTIAL
        assert result.observations[0].hostname == "www.example.com"
