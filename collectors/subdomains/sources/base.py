"""
Abstraction for a subdomain discovery source (passive or active).

Adding a new source means writing one class here that implements
`enumerate()` and adding it to the collector's source list -- nothing in
collector.py needs to change. This is the extension point the platform's
future discovery sources (passive-DNS, DNS wordlist enumeration, etc.)
will use.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..models import SourceType


@dataclass(frozen=True)
class RawCandidate:
    """
    One raw hostname string returned by a source, before normalization
    or scope validation.
    """

    hostname: str
    # A small, source-specific identifier for provenance (e.g. a crt.sh
    # certificate id, or the wordlist entry that produced this candidate
    # for dns_bruteforce). Optional -- not every source has one.
    source_reference: str | None = None


class SubdomainSource(ABC):
    """A source of candidate hostnames for a target domain."""

    #: Machine-readable source identifier used in provenance, e.g.
    #: "certificate_transparency". Stable across implementations of the
    #: same underlying source.
    name: str

    #: Machine-readable method/tool identifier, e.g. "crtsh". Narrower
    #: than `name` -- useful if a source is later backed by more than
    #: one concrete implementation.
    method: str

    #: Whether this source only observes existing public data (PASSIVE,
    #: e.g. Certificate Transparency) or sends queries to the target's
    #: own infrastructure to find candidates (ACTIVE, e.g. DNS wordlist
    #: enumeration). Surfaced in SourceResult for honest reporting.
    source_type: SourceType

    @abstractmethod
    def enumerate(self, domain: str, *, timeout: float) -> list[RawCandidate]:
        """
        Return raw candidate hostnames discovered for `domain`.

        Implementations must raise
        `collectors.subdomains.exceptions.SourceError` on failure
        (timeout, HTTP error, malformed response) rather than returning
        an empty list -- the collector distinguishes "found nothing"
        from "the source failed."
        """
