"""
Minimal local development API for the OSINT investigation frontend.

This is the smallest useful slice of the eventual production architecture
(React -> FastAPI -> DNS Collector -> ... -> PostgreSQL): one endpoint that
runs the existing DNSCollector and returns its structured result. There is
no database and no other collectors wired in yet -- those are future work,
not something this file needs to anticipate.

Run from the OSINT/ project root:

    uvicorn backend.main:app --reload --port 8000
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from collectors.dns.collector import DNSCollector
from collectors.dns.models import DNSCollectorConfig

# The default DNS resolver used when a request does not specify one.
# Configurable per-environment so it is never hardcoded into the collector
# itself -- collectors/dns/collector.py continues to accept `nameservers=None`
# to mean "use the system resolver configuration".
DEFAULT_NAMESERVER = os.environ.get("OSINT_DEFAULT_NAMESERVER", "8.8.8.8")

app = FastAPI(title="OSINT Investigation API")

app.add_middleware(
    CORSMiddleware,
    # Vite auto-increments its port (5173, 5174, ...) if the previous one is
    # still occupied by a leftover dev server, so pinning one exact origin
    # here is fragile -- any localhost/127.0.0.1 port is trusted instead.
    # This is a local dev server; do not carry this pattern into production.
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1):\d+$",
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/api/investigations/dns/{target}")
def investigate_dns(
    target: str,
    nameserver: str | None = Query(
        default=None,
        description=(
            f'DNS resolver to query. Defaults to "{DEFAULT_NAMESERVER}" '
            '(configurable via the OSINT_DEFAULT_NAMESERVER environment '
            'variable). Pass "system" to use the system resolver '
            "configuration instead."
        ),
    ),
    timeout: float = Query(default=3.0, gt=0),
    lifetime: float = Query(default=5.0, gt=0),
) -> dict:
    """
    Run the DNS collector against `target` and return its structured result.

    Invalid targets, NXDOMAIN, timeouts, etc. are not HTTP errors -- the
    collector already represents those as a structured `status: "failed"`
    or `"partial"` result (see DNSCollector._create_failed_collection).
    This endpoint only raises an HTTP error for a malformed request itself.
    """

    if not target or not target.strip():
        raise HTTPException(status_code=400, detail="Target must not be empty.")

    resolved_nameserver = (
        None if nameserver and nameserver.lower() == "system"
        else nameserver or DEFAULT_NAMESERVER
    )

    config = DNSCollectorConfig(
        nameservers=[resolved_nameserver] if resolved_nameserver else None,
        timeout=timeout,
        lifetime=lifetime,
    )

    collector = DNSCollector(config=config)
    result = collector.collect(target)

    return result.to_dict()
