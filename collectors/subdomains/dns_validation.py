"""
Minimal, independent DNS validation for discovered candidate hostnames.

This is deliberately NOT collectors.dns.resolver.DNSResolver. That class
is the DNS collector's internal engine for full-record-type collection
plus related-host resolution -- far more than a subdomain validator
needs, and importing it would couple this collector to DNS collector
internals (which the platform's architecture explicitly keeps
independent; each collector owns its own responsibility).

Instead, this module wraps dnspython directly -- the shared third-party
library both collectors independently depend on -- for exactly what
validation needs: does this hostname resolve, via A/AAAA/CNAME. A little
overlap with DNS collector's exception handling is an accepted tradeoff
for that independence.
"""

from __future__ import annotations

import uuid

import dns.exception
import dns.resolver

from .models import DnsValidationStatus, ResolvedRecord


def validate_hostname(
    hostname: str,
    *,
    nameservers: list[str] | None,
    timeout: float,
    lifetime: float,
) -> tuple[DnsValidationStatus, list[ResolvedRecord]]:
    """
    Attempt A, AAAA, and CNAME lookups for `hostname`.

    Never raises: for this collector's purposes, "does not exist",
    "timed out", and "resolver error" are all simply UNRESOLVED with no
    records -- this is a lightweight existence check, not full DNS
    characterization (that remains the DNS collector's job, which
    distinguishes those cases in detail).
    """

    resolver = _build_resolver(nameservers, timeout, lifetime)
    records = _resolve_records(resolver, hostname)

    status = DnsValidationStatus.RESOLVED if records else DnsValidationStatus.UNRESOLVED
    return status, records


def detect_wildcard_ips(
    parent_domain: str,
    *,
    nameservers: list[str] | None,
    timeout: float,
    lifetime: float,
) -> set[str]:
    """
    Probe for wildcard DNS on `parent_domain` by resolving a random,
    virtually-guaranteed-nonexistent label under it.

    Returns the set of resolved A/AAAA values if a wildcard is active
    (so validated candidates whose own records exactly match can be
    flagged as wildcard matches -- see collector.py), or an empty set
    if the domain does not appear to use wildcard DNS. Costs exactly one
    extra DNS lookup regardless of how many candidates are validated.
    """

    probe_hostname = f"{uuid.uuid4().hex}.{parent_domain}"
    resolver = _build_resolver(nameservers, timeout, lifetime)
    records = _resolve_records(resolver, probe_hostname)

    return {record.value for record in records if record.type in ("A", "AAAA")}


def _build_resolver(
    nameservers: list[str] | None,
    timeout: float,
    lifetime: float,
) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)

    if nameservers:
        resolver.nameservers = nameservers

    resolver.timeout = timeout
    resolver.lifetime = lifetime

    return resolver


def _resolve_records(resolver: dns.resolver.Resolver, hostname: str) -> list[ResolvedRecord]:
    records: list[ResolvedRecord] = []

    for record_type in ("A", "AAAA", "CNAME"):
        try:
            answer = resolver.resolve(hostname, record_type, raise_on_no_answer=False)
        except (dns.exception.DNSException, OSError):
            # NXDOMAIN, timeout, SERVFAIL, REFUSED, and network errors are
            # all treated the same way here: this record type simply
            # didn't resolve. See the module docstring for why this
            # collector does not need DNS collector's finer-grained
            # error classification.
            continue

        if answer.rrset is None:
            continue

        ttl = answer.rrset.ttl

        for rdata in answer:
            if record_type == "CNAME":
                value = str(rdata.target).rstrip(".").lower()
            else:
                value = str(rdata.address)

            records.append(ResolvedRecord(type=record_type, value=value, ttl=ttl))

    return records
