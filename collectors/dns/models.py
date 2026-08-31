"""
Data models for the DNS collector.

These models define the structured output produced by the collector.
They are intentionally independent of dnspython so that the rest of
the OSINT platform does not need to know which DNS library is being used.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class TargetType(str, Enum):
    """Supported DNS collector target types."""

    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IP = "ip"


class CollectionStatus(str, Enum):
    """Overall status of a DNS collection."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class QueryStatus(str, Enum):
    """Status of an individual DNS query."""

    SUCCESS = "success"
    NO_ANSWER = "no_answer"
    NXDOMAIN = "nxdomain"
    TIMEOUT = "timeout"
    SERVFAIL = "servfail"
    REFUSED = "refused"
    ERROR = "error"


@dataclass(frozen=True)
class Target:
    """
    The target supplied to the DNS collector.
    """

    value: str
    type: TargetType


@dataclass(frozen=True)
class CollectorInfo:
    """Information identifying the collector."""

    name: str = "dns"
    version: str = "1.0.0"


@dataclass
class DNSRecord:
    """
    A normalized DNS record.

    Common information is represented by the main fields.
    Record-specific information is stored in attributes.
    """

    type: str
    name: str
    value: str
    ttl: int | None = None
    attributes: dict[str, Any] = field(
        default_factory=dict
    )


@dataclass
class EntityRelationship:
    """
    A relationship discovered through DNS.

    These relationships can later be consumed by the
    investigation graph/correlation engine.
    """

    entity_type: str
    value: str
    relationship: str
    source_record: str


@dataclass
class CollectionError:
    """
    Structured information about an error encountered during collection.
    """

    query_type: str | None
    error_type: str
    message: str
    resolver: str | None = None


@dataclass
class DNSQueryMetadata:
    """
    Metadata describing an individual DNS query.
    """

    query_type: str
    resolver: str
    duration_ms: float
    status: QueryStatus


@dataclass
class DNSCollection:
    """
    Complete result produced by the DNS collector.
    """

    target: Target
    observed_at: str
    collector: CollectorInfo
    status: CollectionStatus

    records: list[DNSRecord] = field(
        default_factory=list
    )

    related_entities: list[EntityRelationship] = field(
        default_factory=list
    )

    queries: list[DNSQueryMetadata] = field(
        default_factory=list
    )

    errors: list[CollectionError] = field(
        default_factory=list
    )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the collection into a JSON-serializable dictionary.
        """

        data = asdict(self)

        data["target"]["type"] = self.target.type.value
        data["status"] = self.status.value

        for query in data["queries"]:
            query["status"] = query["status"].value

        return data


@dataclass
class DNSCollectorConfig:
    """
    Configuration for the DNS collector.

    If nameservers is None, dnspython uses the system resolver
    configuration.

    Related hostname resolution is limited to one level by default.
    """

    nameservers: list[str] | None = None

    timeout: float = 3.0
    lifetime: float = 5.0

    resolve_related_hosts: bool = True

    related_resolution_depth: int = 1

    # Core DNS record types collected by default.
    #
    # DNSSEC-specific records are deliberately excluded from the
    # default collection because they are specialized and can make
    # ordinary collection unnecessarily slow on some resolvers.
    record_types: tuple[str, ...] = (
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
        "SOA",
        "CAA",
    )