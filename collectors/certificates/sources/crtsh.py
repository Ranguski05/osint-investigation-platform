"""
Certificate Transparency source for the certificate intelligence
collector, backed by crt.sh's public JSON search endpoint.

crt.sh indexes Certificate Transparency logs and exposes a simple search
API: https://crt.sh/?q=%.example.com&output=json returns every certificate
whose Subject/SAN matches, as a JSON array of objects, each carrying
(among other fields) `id`, `issuer_name`, `common_name`, `name_value`
(newline-separated CN + SANs), `not_before`, `not_after`, and
`serial_number`.

Deliberately independent of collectors/subdomains/sources/crtsh.py, even
though both talk to the same public service -- see collector.py's module
docstring for why Certificate Intelligence does not import anything from
the Subdomain Enumeration collector. The small amount of duplicated
HTTP-fetch logic is the accepted cost of that independence, matching how
this project already independently redefines other small primitives
(e.g. HOSTNAME_PATTERN) per collector rather than sharing them.

This source deliberately does NOT fetch each certificate's full X.509
data (which would reveal the SHA-256 fingerprint, signature algorithm,
etc.) -- that would mean one additional HTTP request per certificate,
which for a domain with dozens of certificates would turn one bounded
query into an unbounded crawl against public CT infrastructure. See
CertificateObservation's docstring in models.py for the resulting fields
left as None.

Uses stdlib `urllib.request` rather than adding an HTTP client dependency
for what is a single GET request.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from ..exceptions import SourceError
from .base import CertificateSource, RawCertificateEntry

CRTSH_URL = "https://crt.sh/"

# Identifies this platform honestly to the service being queried, per the
# instruction to use an appropriate User-Agent and respect the service --
# crt.sh is a free community resource, not something to hide traffic from.
USER_AGENT = "OSINT-Investigation-Platform/1.0 (passive certificate transparency lookup)"


class CrtShSource(CertificateSource):
    """Discovers certificates from Certificate Transparency logs via crt.sh."""

    name = "certificate_transparency"
    method = "crtsh"

    def search(self, domain: str, *, timeout: float) -> list[RawCertificateEntry]:
        # "%." is crt.sh's ILIKE-style wildcard prefix -- this matches
        # both the bare domain and any subdomain of it in one request, so
        # a single bounded request is enough (see the module docstring's
        # "don't hammer CT infrastructure" reasoning).
        url = f"{CRTSH_URL}?q=%25.{domain}&output=json"

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read()

        except urllib.error.HTTPError as exc:
            raise SourceError(f"crt.sh returned HTTP {exc.code}.") from exc

        except urllib.error.URLError as exc:
            raise SourceError(f"crt.sh request failed: {exc.reason}.") from exc

        except TimeoutError as exc:
            raise SourceError("crt.sh request timed out.") from exc

        try:
            entries = json.loads(body)
        except json.JSONDecodeError as exc:
            raise SourceError("crt.sh returned a response that was not valid JSON.") from exc

        if not isinstance(entries, list):
            raise SourceError("crt.sh returned an unexpected response shape (expected a JSON array).")

        return self._extract_entries(entries)

    @staticmethod
    def _extract_entries(entries: list) -> list[RawCertificateEntry]:
        results: list[RawCertificateEntry] = []

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            name_value = entry.get("name_value")
            if not isinstance(name_value, str) or not name_value.strip():
                continue

            entry_id = entry.get("id")
            if entry_id is None:
                # Without a source reference there is nothing stable to
                # key provenance or deduplication on -- skip rather than
                # inventing one.
                continue

            results.append(
                RawCertificateEntry(
                    source_reference=str(entry_id),
                    name_value=name_value,
                    common_name=_clean_str(entry.get("common_name")),
                    issuer=_clean_str(entry.get("issuer_name")),
                    serial_number=_clean_str(entry.get("serial_number")),
                    not_before=_clean_str(entry.get("not_before")),
                    not_after=_clean_str(entry.get("not_after")),
                )
            )

        return results


def _clean_str(value: object) -> str | None:
    """A present-but-blank string is treated the same as a missing field."""

    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
