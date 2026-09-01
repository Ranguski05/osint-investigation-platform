"""
Utility functions for the certificate collector: target validation, SAN
normalization, timestamp parsing, and validity-status calculation.

This module does not perform any network I/O.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

from .exceptions import InvalidTargetError
from .models import CertificateValidityStatus, SubjectAlternativeName, Target

# Same shape as collectors/dns/utils.py's and
# collectors/subdomains/utils.py's HOSTNAME_PATTERN (a label is 1-63
# chars, alphanumeric with internal hyphens, dot-separated), defined
# independently rather than imported -- see collector.py's module
# docstring for why this collector does not depend on either.
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
    Validate the domain/hostname to gather certificate intelligence for.

    Certificate Transparency search is a domain/hostname concept -- an IP
    address is rejected rather than silently accepted, and a URL (scheme
    or path) is rejected rather than silently reduced to its host, per
    the "do not silently transform bad input" requirement.

    Raises:
        InvalidTargetError: if the target is empty, malformed, an IP, or a URL.
    """

    if not isinstance(value, str):
        raise InvalidTargetError("Target must be a string.")

    value = value.strip()

    if not value:
        raise InvalidTargetError("Target cannot be empty.")

    if "://" in value or "/" in value:
        raise InvalidTargetError(f"Target must be a bare domain/hostname, not a URL: {value}")

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
        raise InvalidTargetError(f"Certificate search requires a domain, not an IP address: {value}")

    return Target(value=normalized)


def normalize_dns_name(raw: str) -> SubjectAlternativeName | None:
    """
    Normalize one raw Subject Alternative Name string into a
    SubjectAlternativeName, or None if it cannot be normalized into a
    plausible DNS name (e.g. an email address SAN, an IP-address SAN, a
    bare "*", or a malformed entry).

    Certificates commonly carry non-DNS SAN types (email, IP, URI) --
    this collector only extracts DNS names, matching the "do NOT blindly
    treat arbitrary SAN strings as hostnames" requirement.
    """

    if not isinstance(raw, str):
        return None

    original = raw.strip()
    if not original:
        return None

    candidate = original.rstrip(".").lower()

    is_wildcard = candidate.startswith("*.")
    name = candidate[2:] if is_wildcard else candidate

    if not name or len(name) > 253:
        return None

    if not HOSTNAME_PATTERN.fullmatch(name):
        return None

    for label in name.split("."):
        if len(label) > 63:
            return None

    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        # An IP-address SAN is not a hostname.
        return None

    return SubjectAlternativeName(name=name, is_wildcard=is_wildcard, raw=original)


def parse_ct_timestamp(raw: str | None) -> str | None:
    """
    Normalize a Certificate Transparency source's timestamp string (e.g.
    crt.sh's "2026-01-01T00:00:00" or "2026-01-01T00:00:00.000") into a
    UTC ISO-8601 string, or None if it is missing or unparseable.

    Never raises -- a malformed single timestamp must not crash the whole
    collection (see collector.py's error-handling requirements).
    """

    if not isinstance(raw, str) or not raw.strip():
        return None

    text = raw.strip()
    text_for_parsing = text[:-1] if text.endswith("Z") else text

    try:
        parsed = datetime.fromisoformat(text_for_parsing)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def compute_validity_status(not_before: str | None, not_after: str | None) -> CertificateValidityStatus:
    """
    Determine whether "now" falls within [not_before, not_after].

    This reflects the validity PERIOD only -- see
    CertificateValidityStatus's docstring for why this is not a trust or
    revocation determination.
    """

    if not not_before or not not_after:
        return CertificateValidityStatus.UNKNOWN

    try:
        starts = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
        ends = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
    except ValueError:
        return CertificateValidityStatus.UNKNOWN

    now = datetime.now(timezone.utc)

    if now < starts:
        return CertificateValidityStatus.NOT_YET_VALID

    if now > ends:
        return CertificateValidityStatus.EXPIRED

    return CertificateValidityStatus.CURRENT
