"""
Tests for collectors/certificates/collector.py.

Sources are replaced with small in-test fakes (implementing
CertificateSource directly) rather than mocking HTTP, so these exercise
the orchestration logic -- SAN extraction, deduplication, bounding,
source failure handling, relationship generation, status calculation --
in isolation from crt.sh-specific parsing (covered in
test_sources_crtsh.py).
"""

from __future__ import annotations

import pytest

from collectors.certificates.collector import CertificateCollector
from collectors.certificates.exceptions import SourceError
from collectors.certificates.models import CertificateCollectorConfig, CertificateValidityStatus, CollectionStatus, SourceStatus
from collectors.certificates.sources.base import CertificateSource, RawCertificateEntry


class FakeSource(CertificateSource):
    def __init__(
        self,
        name: str = "certificate_transparency",
        method: str = "fake",
        entries: list[RawCertificateEntry] | None = None,
        error: Exception | None = None,
    ):
        self.name = name
        self.method = method
        self._entries = entries or []
        self._error = error
        self.calls: list[str] = []

    def search(self, domain: str, *, timeout: float) -> list[RawCertificateEntry]:
        self.calls.append(domain)
        if self._error is not None:
            raise self._error
        return self._entries


def _entry(**overrides) -> RawCertificateEntry:
    defaults = dict(
        source_reference="1",
        name_value="example.com\nwww.example.com",
        common_name="example.com",
        issuer="C=US, O=Let's Encrypt, CN=R3",
        serial_number="serial-1",
        not_before="2000-01-01T00:00:00",
        not_after="2099-01-01T00:00:00",
    )
    defaults.update(overrides)
    return RawCertificateEntry(**defaults)


class TestInputValidation:
    def test_malformed_target_returns_failed_collection_not_an_exception(self):
        collector = CertificateCollector(sources=[FakeSource()])

        result = collector.collect("not a valid host!!")

        assert result.status == CollectionStatus.FAILED
        assert result.errors[0].error_type == "INVALID_TARGET"

    def test_ip_target_is_rejected(self):
        collector = CertificateCollector(sources=[FakeSource()])

        result = collector.collect("93.184.216.34")

        assert result.status == CollectionStatus.FAILED

    def test_url_target_is_rejected(self):
        collector = CertificateCollector(sources=[FakeSource()])

        result = collector.collect("https://example.com")

        assert result.status == CollectionStatus.FAILED

    def test_empty_target_is_rejected(self):
        collector = CertificateCollector(sources=[FakeSource()])

        result = collector.collect("")

        assert result.status == CollectionStatus.FAILED

    def test_no_source_calls_made_for_invalid_target(self):
        source = FakeSource()
        collector = CertificateCollector(sources=[source])

        collector.collect("not a valid host!!")

        assert source.calls == []


class TestSuccessfulCollection:
    def test_single_certificate_produces_one_observation(self):
        collector = CertificateCollector(sources=[FakeSource(entries=[_entry()])])

        result = collector.collect("example.com")

        assert result.status == CollectionStatus.SUCCESS
        assert len(result.certificates) == 1
        cert = result.certificates[0]
        assert cert.common_name == "example.com"
        assert cert.issuer == "C=US, O=Let's Encrypt, CN=R3"
        assert cert.serial_number == "serial-1"

    def test_sans_are_extracted(self):
        collector = CertificateCollector(sources=[FakeSource(entries=[_entry()])])

        result = collector.collect("example.com")

        names = {san.name for san in result.certificates[0].sans}
        assert names == {"example.com", "www.example.com"}

    def test_empty_source_result_is_success_not_failure(self):
        collector = CertificateCollector(sources=[FakeSource(entries=[])])

        result = collector.collect("example.com")

        assert result.status == CollectionStatus.SUCCESS
        assert result.certificates == []
        assert result.candidate_count == 0

    def test_provenance_fields_populated(self):
        collector = CertificateCollector(sources=[FakeSource(entries=[_entry(source_reference="42")])])

        result = collector.collect("example.com")

        cert = result.certificates[0]
        assert cert.source == "certificate_transparency"
        assert cert.method == "crtsh"
        assert cert.source_reference == "42"
        assert cert.observed_at == result.observed_at

    def test_collector_info_present(self):
        collector = CertificateCollector(sources=[FakeSource(entries=[_entry()])])

        result = collector.collect("example.com")

        assert result.collector.name == "certificates"
        assert result.collector.version == CertificateCollector.VERSION


class TestSanNormalizationDuringCollection:
    def test_wildcard_san_preserved(self):
        collector = CertificateCollector(
            sources=[FakeSource(entries=[_entry(name_value="example.com\n*.example.com")])]
        )

        result = collector.collect("example.com")

        wildcard_sans = [san for san in result.certificates[0].sans if san.is_wildcard]
        assert len(wildcard_sans) == 1
        assert wildcard_sans[0].name == "example.com"
        assert result.certificates[0].has_wildcard_san is True

    def test_duplicate_sans_within_one_certificate_are_deduplicated(self):
        collector = CertificateCollector(
            sources=[FakeSource(entries=[_entry(name_value="api.example.com\napi.example.com")])]
        )

        result = collector.collect("example.com")

        names = [san.name for san in result.certificates[0].sans]
        assert names.count("api.example.com") == 1

    def test_uppercase_sans_normalized(self):
        collector = CertificateCollector(sources=[FakeSource(entries=[_entry(name_value="API.EXAMPLE.COM")])])

        result = collector.collect("example.com")

        assert result.certificates[0].sans[0].name == "api.example.com"

    def test_trailing_dot_sans_normalized(self):
        collector = CertificateCollector(sources=[FakeSource(entries=[_entry(name_value="api.example.com.")])])

        result = collector.collect("example.com")

        assert result.certificates[0].sans[0].name == "api.example.com"

    def test_malformed_san_is_ignored_not_crashing(self):
        collector = CertificateCollector(
            sources=[FakeSource(entries=[_entry(name_value="admin@example.com\napi.example.com")])]
        )

        result = collector.collect("example.com")

        names = {san.name for san in result.certificates[0].sans}
        assert names == {"api.example.com"}

    def test_certificate_with_only_invalid_sans_is_skipped(self):
        collector = CertificateCollector(sources=[FakeSource(entries=[_entry(name_value="admin@example.com")])])

        result = collector.collect("example.com")

        assert result.certificates == []
        assert result.status == CollectionStatus.SUCCESS


class TestDeduplication:
    def test_same_certificate_returned_twice_deduplicates_to_one(self):
        entries = [
            _entry(source_reference="1", issuer="Issuer A", serial_number="serial-1"),
            _entry(source_reference="2", issuer="Issuer A", serial_number="serial-1"),
        ]
        collector = CertificateCollector(sources=[FakeSource(entries=entries)])

        result = collector.collect("example.com")

        assert len(result.certificates) == 1

    def test_deduplication_merges_sans_from_both_observations(self):
        entries = [
            _entry(source_reference="1", issuer="Issuer A", serial_number="serial-1", name_value="example.com"),
            _entry(
                source_reference="2",
                issuer="Issuer A",
                serial_number="serial-1",
                name_value="example.com\napi.example.com",
            ),
        ]
        collector = CertificateCollector(sources=[FakeSource(entries=entries)])

        result = collector.collect("example.com")

        names = {san.name for san in result.certificates[0].sans}
        assert names == {"example.com", "api.example.com"}

    def test_different_serial_numbers_remain_distinct_certificates(self):
        entries = [
            _entry(source_reference="1", issuer="Issuer A", serial_number="serial-1"),
            _entry(source_reference="2", issuer="Issuer A", serial_number="serial-2"),
        ]
        collector = CertificateCollector(sources=[FakeSource(entries=entries)])

        result = collector.collect("example.com")

        assert len(result.certificates) == 2

    def test_same_hostname_across_two_certificates_remains_two_certificates(self):
        entries = [
            _entry(source_reference="1", issuer="Issuer A", serial_number="serial-1", name_value="api.example.com"),
            _entry(source_reference="2", issuer="Issuer B", serial_number="serial-2", name_value="api.example.com"),
        ]
        collector = CertificateCollector(sources=[FakeSource(entries=entries)])

        result = collector.collect("example.com")

        assert len(result.certificates) == 2
        for cert in result.certificates:
            assert any(san.name == "api.example.com" for san in cert.sans)

    def test_missing_issuer_or_serial_falls_back_to_source_reference_identity(self):
        entries = [
            _entry(source_reference="1", issuer=None, serial_number=None),
            _entry(source_reference="1", issuer=None, serial_number=None),
            _entry(source_reference="2", issuer=None, serial_number=None),
        ]
        collector = CertificateCollector(sources=[FakeSource(entries=entries)])

        result = collector.collect("example.com")

        assert len(result.certificates) == 2

    def test_exact_and_wildcard_san_on_same_name_both_preserved(self):
        collector = CertificateCollector(
            sources=[FakeSource(entries=[_entry(name_value="example.com\n*.example.com")])]
        )

        result = collector.collect("example.com")

        sans = result.certificates[0].sans
        assert len(sans) == 2
        assert {(san.name, san.is_wildcard) for san in sans} == {("example.com", False), ("example.com", True)}


class TestValidityStatus:
    def test_current_certificate_status(self):
        collector = CertificateCollector(
            sources=[FakeSource(entries=[_entry(not_before="2000-01-01T00:00:00", not_after="2099-01-01T00:00:00")])]
        )

        result = collector.collect("example.com")

        assert result.certificates[0].status == CertificateValidityStatus.CURRENT

    def test_expired_certificate_status(self):
        collector = CertificateCollector(
            sources=[FakeSource(entries=[_entry(not_before="2000-01-01T00:00:00", not_after="2001-01-01T00:00:00")])]
        )

        result = collector.collect("example.com")

        assert result.certificates[0].status == CertificateValidityStatus.EXPIRED

    def test_missing_dates_yield_unknown_status(self):
        collector = CertificateCollector(
            sources=[FakeSource(entries=[_entry(not_before=None, not_after=None)])]
        )

        result = collector.collect("example.com")

        assert result.certificates[0].status == CertificateValidityStatus.UNKNOWN


class TestSourceFailureHandling:
    def test_source_error_is_recorded_structurally(self):
        collector = CertificateCollector(sources=[FakeSource(error=SourceError("crt.sh returned HTTP 502."))])

        result = collector.collect("example.com")

        assert result.status == CollectionStatus.FAILED
        assert result.sources[0].status == SourceStatus.FAILED
        assert result.sources[0].error_type == "SOURCE_ERROR"
        assert result.errors[0].message == "crt.sh returned HTTP 502."

    def test_source_error_does_not_raise(self):
        collector = CertificateCollector(sources=[FakeSource(error=SourceError("boom"))])

        # Must not raise -- failures are structured, not exceptions.
        result = collector.collect("example.com")
        assert result is not None

    def test_unexpected_exception_from_source_is_caught(self):
        collector = CertificateCollector(sources=[FakeSource(error=RuntimeError("unexpected bug"))])

        result = collector.collect("example.com")

        assert result.status == CollectionStatus.FAILED
        assert result.sources[0].error_type == "UNEXPECTED_ERROR"

    def test_partial_status_when_one_of_two_sources_fails(self):
        good = FakeSource(name="a", entries=[_entry(source_reference="1")])
        bad = FakeSource(name="b", error=SourceError("down"))
        collector = CertificateCollector(sources=[good, bad])

        result = collector.collect("example.com")

        assert result.status == CollectionStatus.PARTIAL
        assert len(result.certificates) == 1

    def test_no_sources_configured_is_failed(self):
        collector = CertificateCollector(sources=[])

        result = collector.collect("example.com")

        assert result.status == CollectionStatus.FAILED


class TestMaxCertificatesLimit:
    def test_truncation_flag_set_when_exceeding_limit(self):
        entries = [
            _entry(source_reference=str(i), issuer=f"Issuer {i}", serial_number=str(i), name_value=f"host{i}.example.com")
            for i in range(5)
        ]
        config = CertificateCollectorConfig(max_certificates=3)
        collector = CertificateCollector(config=config, sources=[FakeSource(entries=entries)])

        result = collector.collect("example.com")

        assert result.truncated is True
        assert len(result.certificates) == 3
        assert result.candidate_count == 5

    def test_no_truncation_when_within_limit(self):
        entries = [_entry(source_reference="1")]
        config = CertificateCollectorConfig(max_certificates=200)
        collector = CertificateCollector(config=config, sources=[FakeSource(entries=entries)])

        result = collector.collect("example.com")

        assert result.truncated is False

    def test_truncation_keeps_newest_certificates(self):
        entries = [
            _entry(
                source_reference="old",
                issuer="Issuer",
                serial_number="old",
                not_before="2000-01-01T00:00:00",
                not_after="2001-01-01T00:00:00",
                name_value="old.example.com",
            ),
            _entry(
                source_reference="new",
                issuer="Issuer",
                serial_number="new",
                not_before="2020-01-01T00:00:00",
                not_after="2021-01-01T00:00:00",
                name_value="new.example.com",
            ),
        ]
        config = CertificateCollectorConfig(max_certificates=1)
        collector = CertificateCollector(config=config, sources=[FakeSource(entries=entries)])

        result = collector.collect("example.com")

        assert len(result.certificates) == 1
        assert result.certificates[0].certificate_id == "new"


class TestRelatedEntities:
    def test_covered_hostname_produces_relationship(self):
        collector = CertificateCollector(
            sources=[FakeSource(entries=[_entry(name_value="api.example.com")])]
        )

        result = collector.collect("example.com")

        assert any(
            entity.value == "api.example.com" and entity.relationship == "covered_by_certificate"
            for entity in result.related_entities
        )

    def test_target_itself_gets_domain_entity_type(self):
        collector = CertificateCollector(sources=[FakeSource(entries=[_entry(name_value="example.com")])])

        result = collector.collect("example.com")

        entity = next(e for e in result.related_entities if e.value == "example.com")
        assert entity.entity_type == "domain"

    def test_other_hostname_gets_hostname_entity_type(self):
        collector = CertificateCollector(sources=[FakeSource(entries=[_entry(name_value="api.example.com")])])

        result = collector.collect("example.com")

        entity = next(e for e in result.related_entities if e.value == "api.example.com")
        assert entity.entity_type == "hostname"

    def test_invalid_san_produces_no_relationship(self):
        collector = CertificateCollector(
            sources=[FakeSource(entries=[_entry(name_value="admin@example.com\napi.example.com")])]
        )

        result = collector.collect("example.com")

        values = {entity.value for entity in result.related_entities}
        assert "admin@example.com" not in values

    def test_no_duplicate_relationship_for_wildcard_plus_exact_same_name(self):
        collector = CertificateCollector(
            sources=[FakeSource(entries=[_entry(name_value="example.com\n*.example.com")])]
        )

        result = collector.collect("example.com")

        matching = [e for e in result.related_entities if e.value == "example.com"]
        assert len(matching) == 1

    def test_source_record_points_to_certificate_id(self):
        collector = CertificateCollector(
            sources=[FakeSource(entries=[_entry(source_reference="99", name_value="api.example.com")])]
        )

        result = collector.collect("example.com")

        entity = next(e for e in result.related_entities if e.value == "api.example.com")
        assert entity.source_record == "99"
