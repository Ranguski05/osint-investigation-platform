"""
Utility functions for the DNS collector.

This module contains helper functions for:

- Generating UTC timestamps
- Validating investigation targets
- Classifying targets as domains, hostnames, or IP addresses
- Normalizing DNS names

This module does not perform DNS queries.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

from .exceptions import InvalidTargetError
from .models import Target, TargetType


# Maximum length of a complete DNS hostname is 253 characters.
#
# Each individual DNS label can contain:
# - Letters
# - Numbers
# - Hyphens
#
# A label cannot start or end with a hyphen and cannot exceed
# 63 characters.
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"(?:"
    r"[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"\."
    r")*"
    r"[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"\.?$"
)


def utc_now_iso() -> str:
    """
    Return the current UTC timestamp in ISO-8601 format.

    Example:

        2026-08-31T16:30:42.123Z

    Returns:
        Current UTC timestamp as a string.
    """

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def classify_target(value: str) -> Target:
    """
    Validate and classify an investigation target.

    Supported targets are:

    - IPv4 addresses
    - IPv6 addresses
    - Domains
    - Hostnames

    Args:
        value:
            Target supplied by the user or another collector.

    Returns:
        A validated Target object.

    Raises:
        InvalidTargetError:
            If the target is empty or malformed.
    """

    if not isinstance(value, str):
        raise InvalidTargetError(
            "Target must be a string."
        )

    value = value.strip()

    if not value:
        raise InvalidTargetError(
            "Target cannot be empty."
        )

    # Check whether the target is an IP address.
    try:
        ipaddress.ip_address(value)

        return Target(
            value=value,
            type=TargetType.IP,
        )

    except ValueError:
        # It wasn't an IP address.
        # Continue with hostname validation.
        pass

    # Remove an optional trailing DNS root dot.
    normalized = value.rstrip(".")

    if not normalized:
        raise InvalidTargetError(
            f"Invalid domain or hostname: {value}"
        )

    if len(normalized) > 253:
        raise InvalidTargetError(
            f"Domain or hostname is too long: {value}"
        )

    if not HOSTNAME_PATTERN.fullmatch(normalized):
        raise InvalidTargetError(
            f"Invalid domain or hostname: {value}"
        )

    labels = normalized.split(".")

    for label in labels:
        if len(label) > 63:
            raise InvalidTargetError(
                f"Hostname label exceeds 63 characters: {label}"
            )

    # This is a lightweight classification.
    #
    # DNS resolution itself does not require us to perfectly distinguish
    # domain names from hostnames. The distinction is useful metadata
    # for the larger OSINT platform.
    if len(labels) >= 2:
        target_type = TargetType.DOMAIN
    else:
        target_type = TargetType.HOSTNAME

    return Target(
        value=normalized.lower(),
        type=target_type,
    )


def normalize_dns_name(value: str) -> str:
    """
    Normalize a DNS name for consistent storage.

    DNS names are case-insensitive and DNS libraries commonly
    represent fully qualified names with a trailing dot.

    The DNS root "." is preserved because it is meaningful,
    particularly for records such as a null MX record.

    Examples:

        EXAMPLE.COM.       -> example.com
        Mail.EXAMPLE.COM.  -> mail.example.com
        ns1.example.com.   -> ns1.example.com
        .                  -> .
    """

    value = value.strip()

    if value == ".":
        return "."

    return value.rstrip(".").lower()


def normalize_txt_value(value: str) -> str:
    """
    Perform minimal normalization of a TXT record.

    TXT records can contain arbitrary data, so we deliberately
    avoid interpreting or modifying their contents.

    Args:
        value:
            TXT record value.

    Returns:
        TXT value with surrounding whitespace removed.
    """

    return value.strip()