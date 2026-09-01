"""
Abstraction for a passive subdomain discovery source.

Adding a new source means writing one class here that implements
`enumerate()` and adding it to the collector's source list -- nothing in
collector.py needs to change. This is the extension point the platform's
future passive-DNS/other sources will use.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class RawCandidate:
    """
    One raw hostname string returned by a source, before normalization
    or scope validation.
    """

    hostname: str
    # A small, source-specific identifier for provenance (e.g. a crt.sh
    # certificate id). Optional -- not every source has one.
    source_reference: str | None = None


class SubdomainSource(ABC):
    """A passive source of candidate hostnames for a target domain."""

    #: Machine-readable source identifier used in provenance, e.g.
    #: "certificate_transparency". Stable across implementations of the
    #: same underlying source.
    name: str

    #: Machine-readable method/tool identifier, e.g. "crtsh". Narrower
    #: than `name` -- useful if a source is later backed by more than
    #: one concrete implementation.
    method: str

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
