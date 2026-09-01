"""
Tests for collectors/subdomains/models.py.

Focused on serialization -- the collector's output must be valid JSON
with the expected shape -- and config defaults.
"""

from __future__ import annotations

import json

from collectors.subdomains.models import (
    CollectionStatus,
    CollectorInfo,
    DiscoveryEvidence,
    DnsValidationStatus,
    EntityRelationship,
    ResolvedRecord,
    SourceResult,
    SourceStatus,
    SourceType,
    SubdomainCollection,
    SubdomainCollectorConfig,
    SubdomainObservation,
    Target,
)


def _sample_collection(**overrides) -> SubdomainCollection:
    defaults = dict(
        target=Target(value="example.com"),
        observed_at="2026-01-01T00:00:00.000Z",
        collector=CollectorInfo(version="1.0.0"),
        status=CollectionStatus.SUCCESS,
        observations=[
            SubdomainObservation(
                hostname="api.example.com",
                parent_domain="example.com",
                discovery=[
                    DiscoveryEvidence(
                        source="certificate_transparency",
                        method="crtsh",
                        observed_at="2026-01-01T00:00:00.000Z",
                        source_reference="123",
                    )
                ],
                dns_status=DnsValidationStatus.RESOLVED,
                dns_records=[ResolvedRecord(type="A", value="1.2.3.4", ttl=300)],
            )
        ],
        related_entities=[
            EntityRelationship(
                entity_type="hostname",
                value="api.example.com",
                relationship="discovered_subdomain",
                source_record="certificate_transparency",
            )
        ],
        sources=[SourceResult(source="certificate_transparency", status=SourceStatus.SUCCESS, candidate_count=1)],
        errors=[],
    )
    defaults.update(overrides)
    return SubdomainCollection(**defaults)


class TestSerialization:
    def test_round_trips_through_json(self):
        data = json.loads(json.dumps(_sample_collection().to_dict()))

        assert data["target"] == {"value": "example.com"}
        assert data["status"] == "success"
        assert data["observations"][0]["hostname"] == "api.example.com"
        assert data["observations"][0]["dns_status"] == "resolved"
        assert data["observations"][0]["discovery"][0]["source"] == "certificate_transparency"
        assert data["observations"][0]["dns_records"][0]["value"] == "1.2.3.4"
        assert data["sources"][0]["status"] == "success"
        assert data["related_entities"][0]["relationship"] == "discovered_subdomain"

    def test_not_checked_dns_status_serializes(self):
        observation = SubdomainObservation(hostname="a.example.com", parent_domain="example.com")

        data = _sample_collection(observations=[observation]).to_dict()

        assert data["observations"][0]["dns_status"] == "not_checked"

    def test_wildcard_match_flag_serializes(self):
        observation = SubdomainObservation(hostname="a.example.com", parent_domain="example.com", is_wildcard_match=True)

        data = _sample_collection(observations=[observation]).to_dict()

        assert data["observations"][0]["is_wildcard_match"] is True

    def test_empty_collection_still_serializes(self):
        collection = SubdomainCollection(
            target=Target(value="example.com"),
            observed_at="2026-01-01T00:00:00.000Z",
            collector=CollectorInfo(version="1.0.0"),
            status=CollectionStatus.FAILED,
        )

        data = json.loads(json.dumps(collection.to_dict()))

        assert data["observations"] == []
        assert data["related_entities"] == []
        assert data["sources"] == []
        assert data["errors"] == []

    def test_multi_source_evidence_is_preserved_in_full(self):
        observation = SubdomainObservation(
            hostname="api.example.com",
            parent_domain="example.com",
            discovery=[
                DiscoveryEvidence(source="certificate_transparency", method="crtsh", observed_at="t1"),
                DiscoveryEvidence(source="passive_dns", method="example_pdns", observed_at="t2"),
            ],
        )

        data = _sample_collection(observations=[observation]).to_dict()

        sources = {entry["source"] for entry in data["observations"][0]["discovery"]}
        assert sources == {"certificate_transparency", "passive_dns"}

    def test_failed_source_serializes_error_fields(self):
        source_result = SourceResult(
            source="certificate_transparency",
            status=SourceStatus.FAILED,
            candidate_count=0,
            error_type="SOURCE_ERROR",
            message="crt.sh returned HTTP 502.",
        )

        data = _sample_collection(sources=[source_result]).to_dict()

        assert data["sources"][0]["status"] == "failed"
        assert data["sources"][0]["error_type"] == "SOURCE_ERROR"

    def test_source_type_serializes(self):
        source_result = SourceResult(
            source="dns_bruteforce",
            status=SourceStatus.SUCCESS,
            candidate_count=3,
            source_type=SourceType.ACTIVE,
        )

        data = _sample_collection(sources=[source_result]).to_dict()

        assert data["sources"][0]["source_type"] == "active"

    def test_source_type_defaults_to_passive(self):
        source_result = SourceResult(source="certificate_transparency", status=SourceStatus.SUCCESS, candidate_count=1)

        assert source_result.source_type == SourceType.PASSIVE


class TestCollectorInfo:
    def test_defaults(self):
        info = CollectorInfo()
        assert info.name == "subdomains"
        assert info.version == "1.0.0"


class TestSubdomainCollectorConfigDefaults:
    def test_defaults(self):
        config = SubdomainCollectorConfig()
        assert config.max_candidates == 200
        assert config.validate_dns is False
        assert config.detect_wildcard is True
        assert config.nameservers is None
        assert config.request_timeout == 5.0
