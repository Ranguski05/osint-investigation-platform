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

    `error_type` lets a source distinguish *why* it failed (e.g.
    "AUTH_ERROR", "RATE_LIMITED", "TIMEOUT") in the structured result the
    collector builds. It defaults to the generic "SOURCE_ERROR" so
    existing sources (crt.sh, dns_bruteforce), which never set it, keep
    their exact current behavior.
    """

    def __init__(self, message: str, *, error_type: str = "SOURCE_ERROR") -> None:
        super().__init__(message)
        self.error_type = error_type
