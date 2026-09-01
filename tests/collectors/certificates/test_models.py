"""
Tests for collectors/certificates/models.py.

Focused on serialization -- the collector's output must be valid JSON
with the expected shape -- and config defaults.
"""

from __future__ import annotations

import json

from collectors.certificates.models import (
    CertificateCollection,
    CertificateCollectorConfig,
    CertificateObservation,
    CertificateValidityStatus,
    CollectionStatus,
    CollectorInfo,
    EntityRelationship,
    SourceResult,
    SourceStatus,
    SubjectAlternativeName,
    Target,
)


def _sample_collection(**overrides) -> CertificateCollection:
    defaults = dict(
        target=Target(value="example.com"),
        observed_at="2026-01-01T00:00:00.000Z",
        collector=CollectorInfo(version="1.0.0"),
        status=CollectionStatus.SUCCESS,
        certificates=[
            CertificateObservation(
                certificate_id="123",
                common_name="example.com",
                issuer="C=US, O=Let's Encrypt, CN=R3",
                serial_number="abc123",
                not_before="2026-01-01T00:00:00.000Z",
                not_after="2099-01-01T00:00:00.000Z",
                sans=[
                    SubjectAlternativeName(name="example.com", is_wildcard=False, raw="example.com"),
                    SubjectAlternativeName(name="example.com", is_wildcard=True, raw="*.example.com"),
                ],
                status=CertificateValidityStatus.CURRENT,
                source_reference="123",
                observed_at="2026-01-01T00:00:00.000Z",
            )
        ],
        related_entities=[
            EntityRelationship(
                entity_type="domain",
                value="example.com",
                relationship="covered_by_certificate",
                source_record="123",
            )
        ],
        sources=[SourceResult(source="certificate_transparency", status=SourceStatus.SUCCESS, candidate_count=1)],
        errors=[],
    )
    defaults.update(overrides)
    return CertificateCollection(**defaults)


class TestSerialization:
    def test_round_trips_through_json(self):
        data = json.loads(json.dumps(_sample_collection().to_dict()))

        assert data["target"] == {"value": "example.com"}
        assert data["status"] == "success"
        assert data["certificates"][0]["certificate_id"] == "123"
        assert data["certificates"][0]["status"] == "current"
        assert data["certificates"][0]["sans"][0]["name"] == "example.com"
        assert data["sources"][0]["status"] == "success"
        assert data["related_entities"][0]["relationship"] == "covered_by_certificate"

    def test_has_wildcard_san_serializes_true(self):
        data = _sample_collection().to_dict()
        assert data["certificates"][0]["has_wildcard_san"] is True

    def test_has_wildcard_san_serializes_false(self):
        certificate = CertificateObservation(
            certificate_id="1",
            common_name="example.com",
            issuer="Issuer",
            serial_number="1",
            not_before="2026-01-01T00:00:00.000Z",
            not_after="2099-01-01T00:00:00.000Z",
            sans=[SubjectAlternativeName(name="example.com", is_wildcard=False, raw="example.com")],
        )

        data = _sample_collection(certificates=[certificate]).to_dict()

        assert data["certificates"][0]["has_wildcard_san"] is False

    def test_empty_collection_still_serializes(self):
        collection = CertificateCollection(
            target=Target(value="example.com"),
            observed_at="2026-01-01T00:00:00.000Z",
            collector=CollectorInfo(version="1.0.0"),
            status=CollectionStatus.FAILED,
        )

        data = json.loads(json.dumps(collection.to_dict()))

        assert data["certificates"] == []
        assert data["related_entities"] == []
        assert data["sources"] == []
        assert data["errors"] == []

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

    def test_optional_fields_default_to_none(self):
        certificate = CertificateObservation(
            certificate_id="1",
            common_name=None,
            issuer=None,
            serial_number=None,
            not_before=None,
            not_after=None,
        )

        data = _sample_collection(certificates=[certificate]).to_dict()
        cert_data = data["certificates"][0]

        assert cert_data["common_name"] is None
        assert cert_data["fingerprint_sha256"] is None
        assert cert_data["signature_algorithm"] is None
        assert cert_data["public_key_algorithm"] is None
        assert cert_data["status"] == "unknown"

    def test_unknown_status_is_default(self):
        certificate = CertificateObservation(
            certificate_id="1",
            common_name=None,
            issuer=None,
            serial_number=None,
            not_before=None,
            not_after=None,
        )
        assert certificate.status == CertificateValidityStatus.UNKNOWN


class TestCollectorInfo:
    def test_defaults(self):
        info = CollectorInfo()
        assert info.name == "certificates"
        assert info.version == "1.0.0"


class TestCertificateCollectorConfigDefaults:
    def test_defaults(self):
        config = CertificateCollectorConfig()
        assert config.max_certificates == 200
        assert config.request_timeout == 5.0


class TestSubjectAlternativeName:
    def test_wildcard_and_exact_are_distinct_values(self):
        exact = SubjectAlternativeName(name="example.com", is_wildcard=False, raw="example.com")
        wildcard = SubjectAlternativeName(name="example.com", is_wildcard=True, raw="*.example.com")
        assert exact != wildcard
        assert exact.name == wildcard.name

    def test_frozen(self):
        san = SubjectAlternativeName(name="example.com", is_wildcard=False, raw="example.com")
        try:
            san.name = "changed"  # type: ignore[misc]
            raised = False
        except AttributeError:
            raised = True
        assert raised
