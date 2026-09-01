"""
Data models for the subdomain enumeration collector.

Deliberately independent of collectors/dns/models.py. Several types here
(CollectionStatus, EntityRelationship, CollectionError) are shape-compatible
with their DNS-collector equivalents -- that's intentional, since the
frontend's graph-conversion pattern (records/related_entities -> nodes/
edges) is reused unchanged for this collector -- but they are separately
defined so the two collectors never import each other's internals.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class CollectionStatus(str, Enum):
    """Overall status of a subdomain collection."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class SourceStatus(str, Enum):
    """Outcome of one discovery source's enumeration attempt."""

    SUCCESS = "success"
    FAILED = "failed"


class SourceType(str, Enum):
    """
    Whether a discovery source observes existing public data (passive) or
    actively queries infrastructure to find candidates (active).

    This distinction matters for responsible-use reporting: a passive
    source (e.g. Certificate Transparency) never sends traffic to the
    target; an active source (e.g. DNS wordlist enumeration) does.
    """

    PASSIVE = "passive"
    ACTIVE = "active"


class DnsValidationStatus(str, Enum):
    """
    Whether a discovered hostname's DNS resolution was checked, and if so,
    what was found.

    Discovery and validation are separate concepts (see collector.py):
    NOT_CHECKED means validate_dns was off, not that the hostname is
    somehow suspect.
    """

    NOT_CHECKED = "not_checked"
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class Target:
    """The domain being enumerated."""

    value: str


@dataclass(frozen=True)
class CollectorInfo:
    """Information identifying the collector."""

    name: str = "subdomains"
    version: str = "1.0.0"


@dataclass
class DiscoveryEvidence:
    """
    One source's contribution toward discovering a hostname.

    A hostname can accumulate multiple entries here if more than one
    source independently found it -- see collector.py's deduplication,
    which appends rather than overwrites.
    """

    source: str
    method: str
    observed_at: str
    # A small, source-specific identifier (e.g. a crt.sh certificate id).
    # Never the full raw source response -- see the module docstring in
    # sources/crtsh.py for why.
    source_reference: str | None = None


@dataclass
class ResolvedRecord:
    """
    A single DNS record observed during optional validation.

    Intentionally independent of collectors.dns.models.DNSRecord: this
    collector performs a narrow, unrelated-to-DNS-collector validation
    (see dns_validation.py), not full DNS characterization.
    """

    type: str
    value: str
    ttl: int | None = None


@dataclass
class SubdomainObservation:
    """
    A single discovered hostname, with full discovery provenance and
    optional DNS validation results.
    """

    hostname: str
    parent_domain: str

    discovery: list[DiscoveryEvidence] = field(default_factory=list)

    dns_status: DnsValidationStatus = DnsValidationStatus.NOT_CHECKED
    dns_records: list[ResolvedRecord] = field(default_factory=list)

    # True if this hostname's resolved A/AAAA exactly match the parent
    # domain's detected wildcard DNS response -- see collector.py's
    # wildcard handling. Metadata only; never used to invent candidates.
    is_wildcard_match: bool = False


@dataclass
class SourceResult:
    """Per-source outcome, so one failing source doesn't hide from the caller."""

    source: str
    status: SourceStatus
    candidate_count: int
    error_type: str | None = None
    # `message` also carries non-error, informational notices for an
    # otherwise-successful source (e.g. a wildcard-DNS notice from
    # dns_bruteforce) -- not exclusively an error field.
    message: str | None = None
    # Defaults to PASSIVE rather than being required so every existing
    # call site/test that predates this field keeps working unchanged;
    # collector.py always passes the source's real value explicitly.
    source_type: SourceType = SourceType.PASSIVE


@dataclass
class EntityRelationship:
    """
    A relationship discovered through subdomain enumeration.

    Field-for-field compatible with collectors.dns.models.EntityRelationship
    (not imported from it) so the frontend's existing graph-conversion
    pipeline works unchanged for this collector too.
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
class SubdomainCollection:
    """Complete result produced by the subdomain collector."""

    target: Target
    observed_at: str
    collector: CollectorInfo
    status: CollectionStatus

    observations: list[SubdomainObservation] = field(default_factory=list)
    related_entities: list[EntityRelationship] = field(default_factory=list)
    sources: list[SourceResult] = field(default_factory=list)
    errors: list[CollectionError] = field(default_factory=list)

    candidate_count: int = 0
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert the collection into a JSON-serializable dictionary."""

        data = asdict(self)

        data["status"] = self.status.value

        for observation, observation_data in zip(self.observations, data["observations"]):
            observation_data["dns_status"] = observation.dns_status.value

        for source_result, source_data in zip(self.sources, data["sources"]):
            source_data["status"] = source_result.status.value
            source_data["source_type"] = source_result.source_type.value

        return data


@dataclass
class SubdomainCollectorConfig:
    """Configuration for the subdomain collector."""

    # Upper bound on how many discovered candidates are kept/validated.
    # Discovery sources like crt.sh can return thousands of names for a
    # large domain; this is the primary defense against an accidental
    # query explosion during DNS validation.
    max_candidates: int = 200

    # DNS validation is opt-in: discovery (does this hostname appear to
    # exist, per a passive source) and validation (does it currently
    # resolve) are different questions -- see DnsValidationStatus.
    validate_dns: bool = False

    # HTTP timeout for discovery sources.
    request_timeout: float = 5.0

    # DNS validation timeout/lifetime -- independent of, and typically
    # tighter than, the DNS collector's own defaults, since this is a
    # lightweight existence check, not full record collection.
    dns_timeout: float = 2.0
    dns_lifetime: float = 3.0

    # If None, dnspython uses the system resolver configuration -- same
    # convention as the DNS collector, never hardcoded to a public resolver.
    nameservers: list[str] | None = None

    # Probe for wildcard DNS before validating candidates, so a validated
    # hostname that only resolves because of a wildcard can be flagged
    # rather than presented as independently confirmed. Only meaningful
    # when validate_dns is True; costs exactly one extra DNS query.
    detect_wildcard: bool = True
