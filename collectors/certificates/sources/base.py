"""
Abstraction for a Certificate Transparency (or future certificate-data)
source.

Adding a new source means writing one class here that implements
`search()` and adding it to the collector's source list -- nothing in
collector.py needs to change. Same extension-point pattern as
collectors/subdomains/sources/base.py, defined independently for this
collector (see collector.py's module docstring for why).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class RawCertificateEntry:
    """
    One raw certificate record as returned by a source, before
    normalization or deduplication.

    `name_value` is the raw, possibly newline-separated blob of DNS names
    (CN + SANs) exactly as the source returned it -- normalization and
    per-name splitting happen in collector.py, not here, matching the
    subdomain collector's source/collector split.
    """

    source_reference: str
    name_value: str
    common_name: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    not_before: str | None = None
    not_after: str | None = None


class CertificateSource(ABC):
    """A source of raw certificate records for a target domain."""

    #: Machine-readable source identifier used in provenance, e.g.
    #: "certificate_transparency". Stable across implementations of the
    #: same underlying source.
    name: str

    #: Machine-readable method/tool identifier, e.g. "crtsh". Narrower
    #: than `name` -- useful if a source is later backed by more than one
    #: concrete implementation (e.g. a different CT aggregator).
    method: str

    @abstractmethod
    def search(self, domain: str, *, timeout: float) -> list[RawCertificateEntry]:
        """
        Return raw certificate entries observed for `domain`.

        Implementations must raise
        `collectors.certificates.exceptions.SourceError` on failure
        (timeout, HTTP error, malformed response) rather than returning
        an empty list -- the collector distinguishes "found nothing" from
        "the source failed."
        """
