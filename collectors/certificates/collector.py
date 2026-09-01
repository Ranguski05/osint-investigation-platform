"""
Main orchestration layer for the certificate intelligence collector.

Pipeline:

    sources return raw certificate entries (CN + SAN blob, issuer, serial,
    validity dates, a source-specific row reference)
        -> split/normalize each entry's DNS names (SAN extraction)
        -> deduplicate by certificate identity (issuer, serial_number),
           merging SANs from repeated observations of the same certificate
        -> sort deterministically and bound to max_certificates
        -> compute validity status
        -> structured CertificateCollection (certificates + graph-ready
           related_entities)

This collector is independent of collectors/dns and collectors/subdomains:
it does not import DNSResolver, SubdomainCollector, or either collector's
source implementations, even though its default source (crt.sh) happens
to be the same public service the subdomain collector also queries. Both
independently consume public Certificate Transparency data; neither calls
the other (see collectors/certificates/sources/crtsh.py's module
docstring).
"""

from __future__ import annotations

import logging

from .exceptions import InvalidTargetError, SourceError
from .models import (
    CertificateCollection,
    CertificateCollectorConfig,
    CertificateObservation,
    CollectionError,
    CollectionStatus,
    CollectorInfo,
    EntityRelationship,
    SourceResult,
    SourceStatus,
    SubjectAlternativeName,
    Target,
)
from .sources.base import CertificateSource, RawCertificateEntry
from .sources.crtsh import CrtShSource
from .utils import classify_target, compute_validity_status, normalize_dns_name, parse_ct_timestamp, utc_now_iso

logger = logging.getLogger(__name__)


class CertificateCollector:
    """
    Public interface for certificate intelligence collection.

    Example:

        collector = CertificateCollector()
        result = collector.collect("example.com")
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        config: CertificateCollectorConfig | None = None,
        *,
        sources: list[CertificateSource] | None = None,
    ) -> None:
        """
        Initialize the certificate collector.

        Args:
            config:
                Optional complete CertificateCollectorConfig.

            sources:
                Optional explicit list of Certificate Transparency
                sources. Defaults to a single CrtShSource -- this is the
                extension point for adding more CT sources later without
                changing the collector itself.
        """

        self.config = config or CertificateCollectorConfig()

        if self.config.max_certificates <= 0:
            raise ValueError("max_certificates must be greater than zero.")

        if self.config.request_timeout <= 0:
            raise ValueError("request_timeout must be greater than zero.")

        self.sources: list[CertificateSource] = sources if sources is not None else [CrtShSource()]

    def collect(self, target_value: str) -> CertificateCollection:
        """
        Gather certificate intelligence for a target domain.

        Invalid targets produce a structured failed collection rather
        than raising an exception to the caller.

        Args:
            target_value:
                Domain to search Certificate Transparency logs for.

        Returns:
            CertificateCollection containing certificates, relationships,
            per-source results, and errors.
        """

        observed_at = utc_now_iso()

        try:
            target = classify_target(target_value)
        except InvalidTargetError as exc:
            logger.warning("Rejected invalid certificate target: %r (%s)", target_value, exc)
            return self._create_failed_collection(target_value, observed_at, exc)

        logger.info("Starting certificate collection for %s", target.value)

        collection = CertificateCollection(
            target=target,
            observed_at=observed_at,
            collector=CollectorInfo(version=self.VERSION),
            status=CollectionStatus.SUCCESS,
        )

        # Certificate identity (issuer, serial_number) -- or a fallback
        # key when either is missing -- -> merged raw entries sharing
        # that identity. A dict (not a list) is what makes
        # deduplication-with-merge simple: a second observation of the
        # same certificate folds into the existing entry instead of
        # creating a second one.
        merged_entries: dict[tuple[str, str], list[RawCertificateEntry]] = {}

        for source in self.sources:
            logger.info("Running source %s for %s", source.name, target.value)
            self._run_source(source, target.value, collection, merged_entries)

        observations = self._build_observations(merged_entries, observed_at)

        collection.candidate_count = len(observations)
        collection.truncated = len(observations) > self.config.max_certificates

        if collection.truncated:
            logger.warning(
                "%s discovered %d certificates; keeping only the first %d "
                "(see CertificateCollectorConfig.max_certificates).",
                target.value,
                len(observations),
                self.config.max_certificates,
            )

        collection.certificates = observations[: self.config.max_certificates]

        self._build_related_entities(collection)
        self._calculate_status(collection)

        logger.info(
            "Completed certificate collection for %s: status=%s certificates=%d sources=%d",
            target.value,
            collection.status.value,
            len(collection.certificates),
            len(collection.sources),
        )

        return collection

    def _run_source(
        self,
        source: CertificateSource,
        domain: str,
        collection: CertificateCollection,
        merged_entries: dict[tuple[str, str], list[RawCertificateEntry]],
    ) -> None:
        """
        Run one Certificate Transparency source and fold its raw entries
        into `merged_entries`. A source failure is recorded structurally
        and does not prevent other sources (or already-collected entries)
        from being used.
        """

        try:
            raw_entries = source.search(domain, timeout=self.config.request_timeout)

        except SourceError as exc:
            logger.warning("Source %s failed for %s: %s", source.name, domain, exc)
            self._record_source_failure(collection, source, "SOURCE_ERROR", str(exc))
            return

        except Exception as exc:  # noqa: BLE001 -- a third-party source must never crash the whole collection
            logger.error("Source %s raised an unexpected error for %s: %s", source.name, domain, exc)
            self._record_source_failure(collection, source, "UNEXPECTED_ERROR", str(exc))
            return

        for raw_entry in raw_entries:
            identity = _certificate_identity(raw_entry)
            merged_entries.setdefault(identity, []).append(raw_entry)

        collection.sources.append(
            SourceResult(
                source=source.name,
                status=SourceStatus.SUCCESS,
                candidate_count=len(raw_entries),
            )
        )

    def _record_source_failure(
        self,
        collection: CertificateCollection,
        source: CertificateSource,
        error_type: str,
        message: str,
    ) -> None:
        collection.sources.append(
            SourceResult(
                source=source.name,
                status=SourceStatus.FAILED,
                candidate_count=0,
                error_type=error_type,
                message=message,
            )
        )
        collection.errors.append(
            CollectionError(
                query_type=source.name,
                error_type=error_type,
                message=message,
            )
        )

    def _build_observations(
        self,
        merged_entries: dict[tuple[str, str], list[RawCertificateEntry]],
        observed_at: str,
    ) -> list[CertificateObservation]:
        """
        Turn merged raw entries into normalized CertificateObservations,
        sorted newest-first (missing dates last) for deterministic
        truncation -- a domain with more certificates than
        max_certificates keeps its most recent ones, not an arbitrary
        subset.
        """

        observations: list[CertificateObservation] = []

        for identity, raw_entries in merged_entries.items():
            sans = _merge_sans(raw_entries)

            if not sans:
                # Every raw name on this certificate failed to normalize
                # into a plausible DNS name (e.g. a certificate whose
                # only SANs are email addresses) -- not a malformed
                # certificate, just one with nothing this collector can
                # use. Skip rather than emitting an empty-SAN entity.
                logger.warning(
                    "Certificate %s had no usable DNS names after normalization; skipping.",
                    identity,
                )
                continue

            # Prefer whichever raw entry actually carries issuer/serial/
            # validity metadata -- crt.sh returns these on every row in
            # practice, but a merged identity should not lose metadata
            # just because the first-seen row happened to omit it.
            representative = _pick_representative(raw_entries)

            not_before = parse_ct_timestamp(representative.not_before)
            not_after = parse_ct_timestamp(representative.not_after)

            observations.append(
                CertificateObservation(
                    certificate_id=representative.source_reference,
                    common_name=representative.common_name,
                    issuer=representative.issuer,
                    serial_number=representative.serial_number,
                    not_before=not_before,
                    not_after=not_after,
                    sans=sans,
                    status=compute_validity_status(not_before, not_after),
                    source_reference=representative.source_reference,
                    observed_at=observed_at,
                )
            )

        # Newest first; missing not_before ("") sorts last once reversed,
        # since it's lexicographically smaller than any real ISO-8601
        # timestamp. certificate_id is the final tie-breaker purely for
        # full determinism, not to imply ordering significance.
        observations.sort(
            key=lambda observation: (observation.not_before or "", observation.certificate_id),
            reverse=True,
        )

        return observations

    def _build_related_entities(self, collection: CertificateCollection) -> None:
        """
        Build a flat, graph-relevant summary of which hostnames are
        covered by which certificate.

        This is a best-effort summary for generic/non-certificate-aware
        consumers -- the frontend's certificatesToGraph.ts reads
        `collection.certificates` directly instead, since a certificate
        needs to appear as its own graph node with multiple SAN edges,
        which this flat (entity_type, value, relationship, source_record)
        shape cannot unambiguously express on its own (see collector.py's
        module docstring / the project's certificate-intelligence audit).

        Deduplicated by (value, source_record): a certificate listing
        both "example.com" and "*.example.com" produces two distinct SAN
        entries (see SubjectAlternativeName), but this flat shape has no
        wildcard field to tell them apart, so without deduplication the
        same hostname would appear to be listed twice under one
        certificate.
        """

        seen: set[tuple[str, str]] = set()

        for certificate in collection.certificates:
            for san in certificate.sans:
                key = (san.name, certificate.certificate_id)
                if key in seen:
                    continue
                seen.add(key)

                entity_type = "domain" if san.name == collection.target.value else "hostname"
                collection.related_entities.append(
                    EntityRelationship(
                        entity_type=entity_type,
                        value=san.name,
                        relationship="covered_by_certificate",
                        source_record=certificate.certificate_id,
                    )
                )

    def _create_failed_collection(
        self,
        target_value: str,
        observed_at: str,
        error: InvalidTargetError,
    ) -> CertificateCollection:
        """
        Create a structured result for an invalid target, matching the
        DNS and subdomain collectors' convention of never raising for bad
        input.
        """

        return CertificateCollection(
            target=Target(value=str(target_value)),
            observed_at=observed_at,
            collector=CollectorInfo(version=self.VERSION),
            status=CollectionStatus.FAILED,
            errors=[
                CollectionError(
                    query_type=None,
                    error_type="INVALID_TARGET",
                    message=str(error),
                )
            ],
        )

    @staticmethod
    def _calculate_status(collection: CertificateCollection) -> None:
        """
        Determine the final collection status from per-source outcomes.

        SUCCESS: every source succeeded.
        PARTIAL: at least one source succeeded and at least one failed.
        FAILED: every source failed (or there were no sources at all).

        Truncation and "zero certificates found" (a source that
        succeeded but had nothing to report) do not affect status -- an
        empty result from a working source is not a failure.
        """

        if not collection.sources:
            collection.status = CollectionStatus.FAILED
            return

        if all(source.status == SourceStatus.FAILED for source in collection.sources):
            collection.status = CollectionStatus.FAILED
        elif any(source.status == SourceStatus.FAILED for source in collection.sources):
            collection.status = CollectionStatus.PARTIAL
        else:
            collection.status = CollectionStatus.SUCCESS


def _certificate_identity(entry: RawCertificateEntry) -> tuple[str, str]:
    """
    The stable identity two raw entries are considered "the same
    certificate" under.

    (issuer, serial_number) is the real X.509-standard stable identity
    (RFC 5280: a CA never reuses a serial number), used whenever both are
    available. This is deliberately NOT the source's own row id: for
    crt.sh, `id` identifies a CT log *entry*, and the same certificate
    commonly produces multiple entries (a precertificate plus the final
    certificate, or submissions to more than one log) with different
    ids -- deduplicating on `id` alone would under-deduplicate. When
    issuer/serial are unavailable, the row id is used as a same-tagged
    fallback identity so at least exact-duplicate rows still merge.
    """

    if entry.issuer and entry.serial_number:
        return ("issuer_serial", f"{entry.issuer}|{entry.serial_number}")
    return ("source_reference", entry.source_reference)


def _merge_sans(raw_entries: list[RawCertificateEntry]) -> list[SubjectAlternativeName]:
    """
    Normalize and deduplicate every DNS name across all raw entries that
    share one certificate identity.

    Deduplicated by (name, is_wildcard) rather than by name alone: a
    certificate that lists both "example.com" and "*.example.com" covers
    two meaningfully different things (see SubjectAlternativeName), so
    both are preserved as distinct SAN entries.
    """

    seen: dict[tuple[str, bool], SubjectAlternativeName] = {}

    for raw_entry in raw_entries:
        for raw_name in raw_entry.name_value.split("\n"):
            raw_name = raw_name.strip()
            if not raw_name:
                continue

            san = normalize_dns_name(raw_name)
            if san is None:
                logger.warning("Ignoring unusable SAN entry: %r", raw_name)
                continue

            seen.setdefault((san.name, san.is_wildcard), san)

    return sorted(seen.values(), key=lambda san: (san.name, san.is_wildcard))


def _pick_representative(raw_entries: list[RawCertificateEntry]) -> RawCertificateEntry:
    """
    Choose the raw entry to source certificate-level metadata
    (issuer/serial/validity/CN) from, preferring one that actually has
    validity dates over one that doesn't. Falls back to the first entry
    (sorted by source_reference for determinism) if none do.
    """

    with_dates = [entry for entry in raw_entries if entry.not_before and entry.not_after]
    candidates = with_dates or raw_entries
    return min(candidates, key=lambda entry: entry.source_reference)
