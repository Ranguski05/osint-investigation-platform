"""
Subdomain enumeration collector package.

This module exposes the public components of the subdomain collector so
that the rest of the OSINT platform can import them cleanly.
"""

from .collector import SubdomainCollector
from .models import (
    CollectionError,
    CollectionStatus,
    CollectorInfo,
    DiscoveryEvidence,
    DnsValidationStatus,
    EntityRelationship,
    ResolvedRecord,
    SourceResult,
    SourceStatus,
    SubdomainCollection,
    SubdomainCollectorConfig,
    SubdomainObservation,
    Target,
)

__all__ = [
    "SubdomainCollector",
    "SubdomainCollectorConfig",
    "SubdomainCollection",
    "SubdomainObservation",
    "DiscoveryEvidence",
    "ResolvedRecord",
    "SourceResult",
    "EntityRelationship",
    "CollectionError",
    "CollectorInfo",
    "Target",
    "CollectionStatus",
    "SourceStatus",
    "DnsValidationStatus",
]
