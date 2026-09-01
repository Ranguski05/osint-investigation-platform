"""
Tests for collectors/dns/models.py.

Focused on serialization (the collector's output must be valid JSON with
the expected shape) and config defaults.
"""

from __future__ import annotations

import json

from collectors.dns.models import (
    CollectionError,
    CollectionStatus,
    CollectorInfo,
    DNSCollection,
    DNSCollectorConfig,
    DNSQueryMetadata,
    DNSRecord,
    EntityRelationship,
    QueryStatus,
    Target,
    TargetType,
)


def _sample_collection(**overrides) -> DNSCollection:
    defaults = dict(
        target=Target(value="example.com", type=TargetType.DOMAIN),
        observed_at="2026-01-01T00:00:00.000Z",
        collector=CollectorInfo(version="1.0.0"),
        status=CollectionStatus.SUCCESS,
        records=[DNSRecord(type="A", name="example.com", value="1.2.3.4", ttl=300)],
        related_entities=[
            EntityRelationship(entity_type="ip", value="1.2.3.4", relationship="resolves_to", source_record="A")
        ],
        queries=[DNSQueryMetadata(query_type="A", resolver="8.8.8.8", duration_ms=1.5, status=QueryStatus.SUCCESS)],
        errors=[],
    )
    defaults.update(overrides)
    return DNSCollection(**defaults)


class TestDnsCollectionSerialization:
    def test_to_dict_round_trips_through_json(self):
        data = _sample_collection().to_dict()

        parsed = json.loads(json.dumps(data))

        assert parsed["target"] == {"value": "example.com", "type": "domain"}
        assert parsed["status"] == "success"
        assert parsed["queries"][0]["status"] == "success"
        assert parsed["records"][0]["value"] == "1.2.3.4"
        assert parsed["related_entities"][0]["relationship"] == "resolves_to"

    def test_dnssec_signed_defaults_to_none(self):
        data = _sample_collection().to_dict()
        assert data["dnssec_signed"] is None

    def test_dnssec_signed_true_serializes_as_bool_not_string(self):
        data = _sample_collection(dnssec_signed=True).to_dict()
        assert data["dnssec_signed"] is True

    def test_dnssec_signed_false_serializes_as_bool_not_string(self):
        data = _sample_collection(dnssec_signed=False).to_dict()
        assert data["dnssec_signed"] is False

    def test_empty_collection_still_serializes(self):
        collection = DNSCollection(
            target=Target(value="example.com", type=TargetType.DOMAIN),
            observed_at="2026-01-01T00:00:00.000Z",
            collector=CollectorInfo(version="1.0.0"),
            status=CollectionStatus.FAILED,
        )

        data = json.loads(json.dumps(collection.to_dict()))

        assert data["records"] == []
        assert data["related_entities"] == []
        assert data["queries"] == []
        assert data["errors"] == []

    def test_record_attributes_are_preserved(self):
        record = DNSRecord(
            type="MX",
            name="example.com",
            value="mail.example.com",
            ttl=300,
            attributes={"priority": 10},
        )
        data = _sample_collection(records=[record]).to_dict()
        assert data["records"][0]["attributes"] == {"priority": 10}

    def test_collection_error_serializes_with_query_type_none(self):
        error = CollectionError(query_type=None, error_type="INVALID_TARGET", message="bad target")
        data = _sample_collection(errors=[error]).to_dict()
        assert data["errors"][0]["query_type"] is None
        assert data["errors"][0]["error_type"] == "INVALID_TARGET"


class TestCollectorInfo:
    def test_defaults(self):
        info = CollectorInfo()
        assert info.name == "dns"
        assert info.version == "1.0.0"


class TestDNSCollectorConfigDefaults:
    def test_default_record_types_exclude_dnssec(self):
        config = DNSCollectorConfig()
        assert "A" in config.record_types
        assert "DNSKEY" not in config.record_types
        assert "DS" not in config.record_types

    def test_new_bounding_and_opt_in_defaults(self):
        config = DNSCollectorConfig()
        assert config.max_related_hosts == 10
        assert config.include_dnssec is False
        assert config.resolve_ptr_for_discovered_ips is False

    def test_nameservers_default_to_none_meaning_system_resolver(self):
        config = DNSCollectorConfig()
        assert config.nameservers is None
