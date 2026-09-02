"""
Passive subdomain discovery source backed by SecurityTrails' Subdomains
API.

    GET https://api.securitytrails.com/v1/domain/{domain}/subdomains
        ?children_only=false&include_inactive=true

SecurityTrails returns subdomain *labels* only (e.g. "api", not
"api.example.com") in a `{"subdomains": [...]}` envelope -- this source
joins each label back onto `domain` before handing it to the collector,
same shape every other source returns.

Unlike crt.sh and Cert Spotter, SecurityTrails requires an API key. Per
the project's convention of configuring per-environment values via
`OSINT_*` environment variables rather than hardcoding them (see
DEFAULT_NAMESERVER in backend/main.py), the key is read from
`OSINT_SECURITYTRAILS_API_KEY` when not passed explicitly to the
constructor. A missing key is a clean, structured AUTH_ERROR raised
before any request is made -- not a network call that predictably fails.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from ..exceptions import SourceError
from ..models import SourceType
from .base import RawCandidate, SubdomainSource

SECURITYTRAILS_URL = "https://api.securitytrails.com/v1/domain"

USER_AGENT = "OSINT-Investigation-Platform/1.0 (passive subdomain discovery)"

API_KEY_ENV_VAR = "OSINT_SECURITYTRAILS_API_KEY"

# SecurityTrails does not paginate this endpoint (it returns every known
# subdomain label in one response), but a hard cap still guards against a
# pathological or unexpected response handing back an enormous list --
# the collector's own max_candidates bounds the final result across all
# sources, but a single source should not be the one holding thousands of
# unbounded entries in memory in the meantime.
MAX_RESULTS = 2000


class SecurityTrailsSource(SubdomainSource):
    """Discovers candidate hostnames via the SecurityTrails Subdomains API."""

    name = "securitytrails"
    method = "securitytrails"
    source_type = SourceType.PASSIVE

    def __init__(self, *, api_key: str | None = None) -> None:
        """
        Args:
            api_key: SecurityTrails API key. Falls back to the
                OSINT_SECURITYTRAILS_API_KEY environment variable when
                omitted; if neither is set, enumerate() fails cleanly
                with an AUTH_ERROR rather than making a request.
        """

        self.api_key = api_key if api_key is not None else os.environ.get(API_KEY_ENV_VAR)

    def enumerate(self, domain: str, *, timeout: float) -> list[RawCandidate]:
        if not self.api_key:
            raise SourceError(
                f"SecurityTrails API key not configured (set {API_KEY_ENV_VAR}).",
                error_type="AUTH_ERROR",
            )

        params = urllib.parse.urlencode({"children_only": "false", "include_inactive": "true"})
        url = f"{SECURITYTRAILS_URL}/{urllib.parse.quote(domain)}/subdomains?{params}"

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "APIKEY": self.api_key,
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read()

        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise SourceError("SecurityTrails rejected the configured API key.", error_type="AUTH_ERROR") from exc
            if exc.code == 429:
                raise SourceError("SecurityTrails rate limit exceeded.", error_type="RATE_LIMITED") from exc
            raise SourceError(f"SecurityTrails returned HTTP {exc.code}.") from exc

        except urllib.error.URLError as exc:
            raise SourceError(f"SecurityTrails request failed: {exc.reason}.", error_type="NETWORK_ERROR") from exc

        except TimeoutError as exc:
            raise SourceError("SecurityTrails request timed out.", error_type="TIMEOUT") from exc

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise SourceError(
                "SecurityTrails returned a response that was not valid JSON.",
                error_type="MALFORMED_RESPONSE",
            ) from exc

        if not isinstance(payload, dict) or not isinstance(payload.get("subdomains"), list):
            raise SourceError(
                "SecurityTrails returned an unexpected response shape (expected a 'subdomains' array).",
                error_type="MALFORMED_RESPONSE",
            )

        return self._extract_candidates(payload["subdomains"], domain)

    @staticmethod
    def _extract_candidates(labels: list, domain: str) -> list[RawCandidate]:
        candidates: list[RawCandidate] = []

        for label in labels[:MAX_RESULTS]:
            if not isinstance(label, str) or not label.strip():
                continue

            label = label.strip().strip(".")
            hostname = f"{label}.{domain}" if label else domain

            candidates.append(RawCandidate(hostname=hostname, source_reference=label or None))

        return candidates
