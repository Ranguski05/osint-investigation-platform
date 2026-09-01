"""
Exceptions used by the certificate intelligence collector.

Independent of collectors/dns/exceptions.py and
collectors/subdomains/exceptions.py by design -- this collector does not
depend on either collector's internals (see collector.py).
"""


class CertificateCollectorError(Exception):
    """
    Base exception for all certificate collector errors.

    Other certificate collector exceptions inherit from this class,
    allowing callers to catch all collector-specific errors with:

        except CertificateCollectorError:
            ...
    """


class InvalidTargetError(CertificateCollectorError):
    """
    Raised when the supplied target is not a valid domain/hostname to
    gather certificate intelligence for.
    """


class SourceError(CertificateCollectorError):
    """
    Raised by a CertificateSource when a search fails (HTTP error, timeout,
    malformed response). Caught by the collector and converted into a
    structured SourceResult + CollectionError rather than aborting the
    whole investigation.
    """
