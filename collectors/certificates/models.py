"""
Data models for the certificate intelligence collector.

Deliberately independent of collectors/dns/models.py and
collectors/subdomains/models.py. Several types here (CollectionStatus,
EntityRelationship, CollectionError, SourceResult) are shape-compatible
with their sibling-collector equivalents -- that's intentional, since the
frontend's graph-conversion pattern is reused unchanged for every
collector -- but they are separately defined so collectors never import
each other's internals (see collector.py's module docstring).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class CollectionStatus(str, Enum):
    """Overall status of a certificate collection."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class SourceStatus(str, Enum):
    """Outcome of one Certificate Transparency source's search attempt."""

    SUCCESS = "success"
    FAILED = "failed"


class CertificateValidityStatus(str, Enum):
    """
    Whether a certificate's validity PERIOD currently covers "now" -- this
    is NOT a trust or revocation determination. A certificate can be
    CURRENT and still be revoked, self-signed, or otherwise untrusted by
    browsers; this collector has no access to revocation status (OCSP/CRL)
    and makes no such claim. "current" (not "valid") is used deliberately
    to avoid implying trust.
    """

    CURRENT = "current"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Target:
    """The domain certificate intelligence is being gathered for."""

    value: str


@dataclass(frozen=True)
class CollectorInfo:
    """Information identifying the collector."""

    name: str = "certificates"
    version: str = "1.0.0"


@dataclass(frozen=True)
class SubjectAlternativeName:
    """
    One DNS name from a certificate's Subject Alternative Name extension,
    already normalized (see utils.normalize_dns_name).

    `raw` preserves the original SAN string exactly as the source returned
    it -- evidence is never discarded merely because a normalized form
    also exists (see the module docstring in utils.py).
    """

    name: str
    is_wildcard: bool
    raw: str


@dataclass
class CertificateObservation:
    """
    One deduplicated certificate discovered for the target, with enough
    metadata and provenance to explain where it came from and what it
    covers.

    Certificate identity (see collector.py's deduplication) is (issuer,
    serial_number) when both are available -- the real X.509-standard
    stable identity -- not the source's own row id, which for crt.sh is a
    CT-log-*entry* id and can differ across precert/cert/multi-log
    submissions of what is otherwise the same certificate.
    """

    certificate_id: str
    common_name: str | None
    issuer: str | None
    serial_number: str | None
    not_before: str | None  # ISO-8601 UTC, or None if unavailable/unparseable
    not_after: str | None  # ISO-8601 UTC, or None if unavailable/unparseable

    sans: list[SubjectAlternativeName] = field(default_factory=list)

    # Not available from crt.sh's summary JSON search endpoint without an
    # additional per-certificate request (see sources/crtsh.py) -- left
    # None rather than fetched, per the "don't hammer public CT
    # infrastructure" / "prefer one bounded request" principle. A future
    # source that can supply these affordably may populate them.
    fingerprint_sha256: str | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None

    status: CertificateValidityStatus = CertificateValidityStatus.UNKNOWN

    source: str = "certificate_transparency"
    method: str = "crtsh"
    # The (or one representative) raw source row id this observation was
    # built from -- see collector.py's deduplication for why this is not
    # necessarily unique across certificates.
    source_reference: str | None = None
    observed_at: str = ""

    @property
    def has_wildcard_san(self) -> bool:
        return any(san.is_wildcard for san in self.sans)


@dataclass
class EntityRelationship:
    """
    A relationship discovered through certificate intelligence.

    Field-for-field compatible with collectors.dns.models.EntityRelationship
    and collectors.subdomains.models.EntityRelationship (not imported from
    either) so the frontend's existing graph-conversion pipeline pattern
    extends to this collector too.
    """

    entity_type: str
    value: str
    relationship: str
    source_record: str


@dataclass
class CollectionError:
    """Structured information about an error encountered during collection."""

    query_type: str | None
    error_type: str
    message: str


@dataclass
class SourceResult:
    """Per-source outcome, so one failing source doesn't hide from the caller."""

    source: str
    status: SourceStatus
    candidate_count: int
    error_type: str | None = None
    message: str | None = None


@dataclass
class CertificateCollection:
    """Complete result produced by the certificate collector."""

    target: Target
    observed_at: str
    collector: CollectorInfo
    status: CollectionStatus

    certificates: list[CertificateObservation] = field(default_factory=list)
    related_entities: list[EntityRelationship] = field(default_factory=list)
    sources: list[SourceResult] = field(default_factory=list)
    errors: list[CollectionError] = field(default_factory=list)

    candidate_count: int = 0
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert the collection into a JSON-serializable dictionary."""

        data = asdict(self)

        data["status"] = self.status.value

        for certificate, certificate_data in zip(self.certificates, data["certificates"]):
            certificate_data["status"] = certificate.status.value
            certificate_data["has_wildcard_san"] = certificate.has_wildcard_san

        for source_result, source_data in zip(self.sources, data["sources"]):
            source_data["status"] = source_result.status.value

        return data


@dataclass
class CertificateCollectorConfig:
    """Configuration for the certificate collector."""

    # Upper bound on how many deduplicated certificates are kept. crt.sh
    # can return thousands of rows for a large/old domain; this is the
    # primary defense against an unbounded result set.
    max_certificates: int = 200

    # HTTP timeout for the Certificate Transparency source.
    request_timeout: float = 5.0
