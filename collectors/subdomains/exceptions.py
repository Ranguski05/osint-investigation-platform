"""
Exceptions used by the subdomain enumeration collector.

Independent of collectors/dns/exceptions.py by design -- this collector
does not depend on the DNS collector's internals (see collector.py).
"""


class SubdomainCollectorError(Exception):
    """
    Base exception for all subdomain collector errors.

    Other subdomain collector exceptions inherit from this class, allowing
    callers to catch all collector-specific errors with:

        except SubdomainCollectorError:
            ...
    """


class InvalidTargetError(SubdomainCollectorError):
    """
    Raised when the supplied target is not a valid domain to enumerate
    subdomains for.
    """


class SourceError(SubdomainCollectorError):
    """
    Raised by a SubdomainSource when discovery fails (HTTP error, timeout,
    malformed response). Caught by the collector and converted into a
    structured SourceResult + CollectionError rather than aborting the
    whole investigation.
    """
