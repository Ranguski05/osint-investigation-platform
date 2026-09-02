"""
Certificate Transparency discovery source, backed by SSLMate's Cert
Spotter public API.

Cert Spotter indexes the same underlying CT logs as crt.sh but exposes a
different API shape:

    https://api.certspotter.com/v1/issuances
        ?domain=example.com&include_subdomains=true&expand=dns_names

`expand=dns_names` is what makes a single request sufficient -- without
it, each issuance in the response is just an id and a follow-up request
per certificate would be needed to learn its hostnames, which this
source deliberately avoids (see module docstring in collector.py and the
project's bound-everything instruction).

Anonymous requests are allowed (used when no API key is configured) but
are rate-limited more aggressively by Cert Spotter than authenticated
ones. An API key, when supplied, is sent via HTTP Basic Auth with the
key as the username and an empty password -- Cert Spotter's documented
authentication scheme (not a bearer token or query parameter).

Bounded pagination: Cert Spotter paginates via an opaque `after` cursor
rather than page numbers. This source follows that cursor for at most
`MAX_PAGES` requests, stopping earlier if a page comes back short of
`PAGE_SIZE` (meaning there is nothing left to fetch) -- see
_MAX_CANDIDATES for the same "never download unbounded data" reasoning
applied to crt.sh's single-request approach.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from ..exceptions import SourceError
from ..models import SourceType
from .base import RawCandidate, SubdomainSource

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"

USER_AGENT = "OSINT-Investigation-Platform/1.0 (passive subdomain discovery)"

# Same OSINT_* environment-variable convention as SecurityTrailsSource,
# for the same reason (see sources/securitytrails.py's module docstring)
# -- unlike SecurityTrails, this one is optional: Cert Spotter works
# anonymously, this only raises the rate limit.
API_KEY_ENV_VAR = "OSINT_CERTSPOTTER_API_KEY"

# Cert Spotter's own maximum page size for this endpoint.
PAGE_SIZE = 1000

# Upper bound on how many pages a single enumerate() call will follow via
# the `after` cursor. Keeps this source's worst case bounded (MAX_PAGES *
# PAGE_SIZE candidates) regardless of how large a domain's CT footprint
# is -- the collector's own max_candidates does the final trim across all
# sources, but a single source should not be the one issuing unbounded
# requests to get there.
MAX_PAGES = 3


class CertSpotterSource(SubdomainSource):
    """Discovers candidate hostnames from Certificate Transparency logs via Cert Spotter."""

    name = "certificate_transparency_certspotter"
    method = "certspotter"
    source_type = SourceType.PASSIVE

    def __init__(self, *, api_key: str | None = None) -> None:
        """
        Args:
            api_key: Optional Cert Spotter API key, sent as an HTTP Basic
                Auth username. Falls back to the OSINT_CERTSPOTTER_API_KEY
                environment variable when omitted; if neither is set,
                requests are sent anonymously (subject to Cert Spotter's
                lower anonymous rate limit) -- unlike SecurityTrails,
                Cert Spotter does not require a key to function at all.
        """

        self.api_key = api_key if api_key is not None else os.environ.get(API_KEY_ENV_VAR)

    def enumerate(self, domain: str, *, timeout: float) -> list[RawCandidate]:
        candidates: list[RawCandidate] = []
        after: str | None = None

        for _ in range(MAX_PAGES):
            page = self._fetch_page(domain, timeout=timeout, after=after)

            page_candidates, next_after = self._extract_candidates(page)
            candidates.extend(page_candidates)

            if next_after is None or len(page) < PAGE_SIZE:
                break

            after = next_after

        return candidates

    def _fetch_page(self, domain: str, *, timeout: float, after: str | None) -> list:
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
        if after is not None:
            params["after"] = after

        url = f"{CERTSPOTTER_URL}?{urllib.parse.urlencode(params)}"

        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        }
        if self.api_key:
            token = base64.b64encode(f"{self.api_key}:".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        request = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read()

        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise SourceError("Cert Spotter rate limit exceeded.", error_type="RATE_LIMITED") from exc
            if exc.code in (401, 403):
                raise SourceError("Cert Spotter rejected the configured API key.", error_type="AUTH_ERROR") from exc
            raise SourceError(f"Cert Spotter returned HTTP {exc.code}.") from exc

        except urllib.error.URLError as exc:
            raise SourceError(f"Cert Spotter request failed: {exc.reason}.", error_type="NETWORK_ERROR") from exc

        except TimeoutError as exc:
            raise SourceError("Cert Spotter request timed out.", error_type="TIMEOUT") from exc

        try:
            page = json.loads(body)
        except json.JSONDecodeError as exc:
            raise SourceError(
                "Cert Spotter returned a response that was not valid JSON.",
                error_type="MALFORMED_RESPONSE",
            ) from exc

        if not isinstance(page, list):
            raise SourceError(
                "Cert Spotter returned an unexpected response shape (expected a JSON array).",
                error_type="MALFORMED_RESPONSE",
            )

        return page

    @staticmethod
    def _extract_candidates(page: list) -> tuple[list[RawCandidate], str | None]:
        candidates: list[RawCandidate] = []
        last_id: str | None = None

        for issuance in page:
            if not isinstance(issuance, dict):
                continue

            issuance_id = issuance.get("id")
            if isinstance(issuance_id, str):
                last_id = issuance_id

            source_reference = issuance_id if isinstance(issuance_id, str) else None

            dns_names = issuance.get("dns_names")
            if not isinstance(dns_names, list):
                continue

            for raw_name in dns_names:
                if isinstance(raw_name, str) and raw_name.strip():
                    candidates.append(RawCandidate(hostname=raw_name.strip(), source_reference=source_reference))

        return candidates, last_id
