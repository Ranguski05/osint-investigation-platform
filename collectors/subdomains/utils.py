"""
Utility functions for the subdomain collector: target validation,
hostname normalization, and domain-scope checking.

This module does not perform any network I/O.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

from .exceptions import InvalidTargetError
from .models import Target

# Same shape as collectors/dns/utils.py's HOSTNAME_PATTERN (a label is
# 1-63 chars, alphanumeric with internal hyphens, dot-separated), defined
# independently rather than imported -- see collector.py's module
# docstring for why this collector does not depend on collectors.dns.
_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
HOSTNAME_PATTERN = re.compile(rf"^(?:{_LABEL}\.)*{_LABEL}\.?$")


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 format (e.g. 2026-01-01T00:00:00.000Z)."""

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def classify_target(value: str) -> Target:
    """
    Validate the domain to enumerate subdomains for.

    Subdomain enumeration only makes sense for a domain/hostname -- an
    IP address is rejected rather than silently accepted, since "find
    subdomains of 93.184.216.34" is not a meaningful request.

    Raises:
        InvalidTargetError: if the target is empty, malformed, or an IP.
    """

    if not isinstance(value, str):
        raise InvalidTargetError("Target must be a string.")

    value = value.strip()

    if not value:
        raise InvalidTargetError("Target cannot be empty.")

    normalized = value.rstrip(".").lower()

    if not normalized:
        raise InvalidTargetError(f"Invalid domain: {value}")

    if len(normalized) > 253:
        raise InvalidTargetError(f"Domain is too long: {value}")

    if not HOSTNAME_PATTERN.fullmatch(normalized):
        raise InvalidTargetError(f"Invalid domain: {value}")

    for label in normalized.split("."):
        if len(label) > 63:
            raise InvalidTargetError(f"Domain label exceeds 63 characters: {label}")

    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        raise InvalidTargetError(f"Subdomain enumeration requires a domain, not an IP address: {value}")

    return Target(value=normalized)


def normalize_hostname(value: str) -> str | None:
    """
    Normalize a raw candidate hostname string (e.g. a certificate SAN)
    into a clean, comparable form.

    Returns None if the value cannot be normalized into a plausible
    hostname -- callers should skip such candidates rather than invent
    a name from unusable input (e.g. an email address SAN, a bare "*",
    or a string containing illegal characters).
    """

    if not isinstance(value, str):
        return None

    candidate = value.strip()

    if not candidate:
        return None

    candidate = candidate.rstrip(".").lower()

    # Wildcard certificates commonly list "*.example.com" as a SAN. The
    # wildcard itself is not a discoverable hostname; the base name
    # underneath it is (see collector.py for how this interacts with
    # wildcard DNS detection during validation).
    if candidate.startswith("*."):
        candidate = candidate[2:]

    if not candidate or len(candidate) > 253:
        return None

    if not HOSTNAME_PATTERN.fullmatch(candidate):
        return None

    return candidate


def is_in_scope(hostname: str, parent_domain: str) -> bool:
    """
    True if `hostname` is `parent_domain` itself or a proper subdomain of
    it, using DNS label boundaries rather than substring matching.

    This is what keeps "example.com.attacker.com" and
    "attackerexample.com" out of an "example.com" investigation --
    both contain "example.com" as a substring, but neither is a subdomain
    of it.
    """

    hostname = hostname.rstrip(".").lower()
    parent_domain = parent_domain.rstrip(".").lower()

    return hostname == parent_domain or hostname.endswith("." + parent_domain)
