"""
Certificate Transparency discovery source, backed by crt.sh's public
JSON search endpoint.

crt.sh indexes Certificate Transparency logs and exposes a simple search
API: https://crt.sh/?q=%.example.com&output=json returns every certificate
whose Subject/SAN matches, as a JSON array of objects. The `name_value`
field of each entry can contain multiple newline-separated hostnames
(one certificate commonly covers several SANs).

We deliberately keep only what's needed for provenance (the certificate's
`id`, used as `source_reference`) -- not the full certificate metadata
(issuer, validity dates, serial number, etc.), per the instruction not to
store entire raw responses.

Uses stdlib `urllib.request` rather than adding an HTTP client dependency
for what is a single GET request.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from ..exceptions import SourceError
from .base import RawCandidate, SubdomainSource

CRTSH_URL = "https://crt.sh/"

# Identifies this platform honestly to the service being queried, per the
# instruction to use an appropriate User-Agent and respect the service --
# crt.sh is a free community resource, not something to hide traffic from.
USER_AGENT = "OSINT-Investigation-Platform/1.0 (passive subdomain discovery)"


class CrtShSource(SubdomainSource):
    """Discovers candidate hostnames from Certificate Transparency logs via crt.sh."""

    name = "certificate_transparency"
    method = "crtsh"

    def enumerate(self, domain: str, *, timeout: float) -> list[RawCandidate]:
        # "%." is crt.sh's ILIKE-style wildcard prefix -- this matches
        # both the bare domain and any subdomain of it in one request,
        # so a single query is enough (see collector.py for why this
        # collector avoids issuing more requests than necessary).
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

        return self._extract_candidates(entries)

    @staticmethod
    def _extract_candidates(entries: list) -> list[RawCandidate]:
        candidates: list[RawCandidate] = []

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            name_value = entry.get("name_value")
            if not isinstance(name_value, str):
                continue

            certificate_id = entry.get("id")
            source_reference = str(certificate_id) if certificate_id is not None else None

            # A single certificate commonly lists several SANs, one per line.
            for raw_name in name_value.split("\n"):
                raw_name = raw_name.strip()
                if raw_name:
                    candidates.append(RawCandidate(hostname=raw_name, source_reference=source_reference))

        return candidates
