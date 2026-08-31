"""
Exceptions used by the DNS collector.

Keeping collector-specific exceptions in one module allows callers to
handle different failure conditions cleanly without depending on the
underlying DNS library.
"""


class DNSCollectorError(Exception):
    """
    Base exception for all DNS collector errors.

    Other DNS collector exceptions inherit from this class, allowing
    callers to catch all collector-specific errors with:

        except DNSCollectorError:
            ...
    """


class InvalidTargetError(DNSCollectorError):
    """
    Raised when the supplied target is invalid.

    Examples include malformed domain names, invalid hostnames,
    and invalid IP addresses.
    """


class UnsupportedTargetError(DNSCollectorError):
    """
    Raised when the collector does not support the supplied target type.
    """


class DNSResolutionError(DNSCollectorError):
    """
    Raised when a DNS resolution operation fails unexpectedly.

    Normal DNS conditions such as NXDOMAIN, timeout, or NO_ANSWER
    should generally be represented in the structured collection
    result rather than raised as exceptions.
    """