"""
DNS collector package.

This module exposes the public components of the DNS collector so that
the rest of the OSINT platform can import them cleanly.
"""

from .collector import DNSCollector, DNSCollectorConfig
from .models import (
    CollectionError,
    CollectionStatus,
    CollectorInfo,
    DNSCollection,
    DNSQueryMetadata,
    DNSRecord,
    EntityRelationship,
    QueryStatus,
    Target,
    TargetType,
)

__all__ = [
    "DNSCollector",
    "DNSCollectorConfig",
    "DNSCollection",
    "DNSRecord",
    "DNSQueryMetadata",
    "EntityRelationship",
    "CollectionError",
    "CollectorInfo",
    "Target",
    "TargetType",
    "CollectionStatus",
    "QueryStatus",
]