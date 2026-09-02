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

from collectors.certificates.collector import CertificateCollector
from collectors.certificates.models import CertificateCollectorConfig
from collectors.dns.collector import DNSCollector
from collectors.dns.models import DNSCollectorConfig
from collectors.subdomains.collector import SubdomainCollector
from collectors.subdomains.models import SubdomainCollectorConfig
from collectors.subdomains.sources.base import SubdomainSource
from collectors.subdomains.sources.certspotter import CertSpotterSource
from collectors.subdomains.sources.crtsh import CrtShSource
from collectors.subdomains.sources.dns_bruteforce import DNSBruteforceSource
from collectors.subdomains.sources.securitytrails import SecurityTrailsSource

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
    include_dnssec: bool = Query(
        default=False,
        description="Also collect DNSKEY/DS and report whether the zone appears signed (presence check, not full validation).",
    ),
    max_related_hosts: int = Query(
        default=10,
        ge=0,
        description="Upper bound on how many related hostnames (from NS/MX/CNAME) get their own A/AAAA resolved.",
    ),
    resolve_ptr_for_discovered_ips: bool = Query(
        default=False,
        description="Also attempt a reverse (PTR) lookup for IPs discovered via A/AAAA records, bounded by max_related_hosts.",
    ),
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
        include_dnssec=include_dnssec,
        max_related_hosts=max_related_hosts,
        resolve_ptr_for_discovered_ips=resolve_ptr_for_discovered_ips,
    )

    collector = DNSCollector(config=config)
    result = collector.collect(target)

    return result.to_dict()


@app.get("/api/investigations/subdomains/{target}")
def investigate_subdomains(
    target: str,
    max_candidates: int = Query(
        default=200,
        gt=0,
        description="Maximum number of discovered candidate hostnames to keep.",
    ),
    validate_dns: bool = Query(
        default=False,
        description="Attempt A/AAAA/CNAME resolution for each discovered hostname.",
    ),
    timeout: float = Query(default=5.0, gt=0, description="HTTP request timeout for discovery sources."),
    enable_certspotter: bool = Query(
        default=True,
        description=(
            "Also discover subdomains via Cert Spotter (a second, "
            "independent Certificate Transparency source, alongside "
            "crt.sh). On by default -- like crt.sh, it is passive and "
            "free, and running both gives more complete coverage and "
            "resilience if one is unavailable."
        ),
    ),
    enable_securitytrails: bool = Query(
        default=False,
        description=(
            "Also discover subdomains via the SecurityTrails API. Off "
            "by default, unlike crt.sh/Cert Spotter -- it requires a "
            "paid/quota-limited API key, configured server-side via the "
            "OSINT_SECURITYTRAILS_API_KEY environment variable, not "
            "over this endpoint."
        ),
    ),
    enable_bruteforce: bool = Query(
        default=False,
        description=(
            "Also discover subdomains via bounded, active DNS wordlist "
            "enumeration (sends DNS queries to the target's own "
            "infrastructure), using the built-in wordlist. Off by "
            "default -- Certificate Transparency alone is passive."
        ),
    ),
    bruteforce_max_candidates: int = Query(
        default=100,
        gt=0,
        le=500,
        description=(
            "Maximum number of wordlist entries to test. Capped at 500 "
            "regardless of the requested value, to bound how much active "
            "DNS traffic a single API request can generate."
        ),
    ),
    bruteforce_concurrency: int = Query(
        default=5,
        gt=0,
        le=10,
        description=(
            "Maximum number of concurrent DNS queries during wordlist "
            "enumeration. Capped at 10 regardless of the requested value."
        ),
    ),
) -> dict:
    """
    Run the subdomain collector against `target` and return its
    structured result.

    Independent of /api/investigations/dns -- this collector does not
    call the DNS collector, and a failure here never affects a DNS
    investigation already on screen (see frontend's App.tsx, which
    treats this as optional graph enrichment).

    A custom wordlist is not accepted over this HTTP endpoint -- only
    the built-in default -- since accepting an arbitrary file path or
    payload from a remote caller to drive active DNS enumeration is a
    needless attack surface for a local dev API. Use the CLI's
    `--wordlist` for a custom list.
    """

    if not target or not target.strip():
        raise HTTPException(status_code=400, detail="Target must not be empty.")

    config = SubdomainCollectorConfig(
        max_candidates=max_candidates,
        validate_dns=validate_dns,
        request_timeout=timeout,
    )

    sources: list[SubdomainSource] = [CrtShSource()]

    if enable_certspotter:
        sources.append(CertSpotterSource())

    if enable_securitytrails:
        sources.append(SecurityTrailsSource())

    if enable_bruteforce:
        sources.append(
            DNSBruteforceSource(
                concurrency=bruteforce_concurrency,
                max_words=bruteforce_max_candidates,
                # Reuses the same DEFAULT_NAMESERVER already used by the
                # DNS endpoint above, for the same reason: this process's
                # system resolver configuration is not something to rely
                # on for a local dev API (see investigate_dns's nameserver
                # handling).
                nameservers=[DEFAULT_NAMESERVER],
            )
        )

    collector = SubdomainCollector(config=config, sources=sources)
    result = collector.collect(target)

    return result.to_dict()


@app.get("/api/investigations/certificates/{target}")
def investigate_certificates(
    target: str,
    max_certificates: int = Query(
        default=200,
        gt=0,
        le=500,
        description=(
            "Maximum number of deduplicated certificates to keep. Capped "
            "at 500 regardless of the requested value."
        ),
    ),
    timeout: float = Query(
        default=5.0,
        gt=0,
        description="HTTP request timeout for the Certificate Transparency source.",
    ),
) -> dict:
    """
    Run the certificate collector against `target` and return its
    structured result.

    Independent of /api/investigations/dns and
    /api/investigations/subdomains -- this collector does not call either
    of them, and a failure here never affects a DNS or subdomain
    investigation already on screen (see frontend's App.tsx, which treats
    this as optional graph enrichment, same as subdomains).
    """

    if not target or not target.strip():
        raise HTTPException(status_code=400, detail="Target must not be empty.")

    config = CertificateCollectorConfig(
        max_certificates=max_certificates,
        request_timeout=timeout,
    )

    collector = CertificateCollector(config=config)
    result = collector.collect(target)

    return result.to_dict()
