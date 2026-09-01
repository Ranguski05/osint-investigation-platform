"""
Main orchestration layer for the subdomain enumeration collector.

Pipeline:

    sources discover raw candidate hostname strings
        -> normalize
        -> validate scope (must belong to the target domain)
        -> deduplicate (preserving multi-source provenance)
        -> bound to max_candidates
        -> optionally validate DNS (A/AAAA/CNAME), with wildcard detection
        -> structured SubdomainCollection (observations + graph-ready
           related_entities)

This collector is independent of collectors/dns: it does not import
DNSResolver or any DNS collector model. See dns_validation.py for the
narrow, independent DNS check used during optional validation. DNS
record collection/characterization remains the DNS collector's job.
"""

from __future__ import annotations

import logging

from .dns_validation import detect_wildcard_ips, validate_hostname
from .exceptions import InvalidTargetError, SourceError
from .models import (
    CollectionError,
    CollectionStatus,
    CollectorInfo,
    DiscoveryEvidence,
    EntityRelationship,
    SourceResult,
    SourceStatus,
    SubdomainCollection,
    SubdomainCollectorConfig,
    SubdomainObservation,
    Target,
)
from .sources.base import SubdomainSource
from .sources.crtsh import CrtShSource
from .utils import classify_target, is_in_scope, normalize_hostname, utc_now_iso

logger = logging.getLogger(__name__)


class SubdomainCollector:
    """
    Public interface for subdomain enumeration.

    Example:

        collector = SubdomainCollector()
        result = collector.collect("example.com")
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        config: SubdomainCollectorConfig | None = None,
        *,
        sources: list[SubdomainSource] | None = None,
    ) -> None:
        """
        Initialize the subdomain collector.

        Args:
            config:
                Optional complete SubdomainCollectorConfig.

            sources:
                Optional explicit list of discovery sources. Defaults to
                a single CrtShSource -- this is the extension point for
                adding more passive sources later without changing the
                collector itself.
        """

        self.config = config or SubdomainCollectorConfig()

        if self.config.max_candidates <= 0:
            raise ValueError("max_candidates must be greater than zero.")

        if self.config.request_timeout <= 0:
            raise ValueError("request_timeout must be greater than zero.")

        if self.config.dns_timeout <= 0:
            raise ValueError("dns_timeout must be greater than zero.")

        if self.config.dns_lifetime <= 0:
            raise ValueError("dns_lifetime must be greater than zero.")

        self.sources: list[SubdomainSource] = sources if sources is not None else [CrtShSource()]

    def collect(self, target_value: str) -> SubdomainCollection:
        """
        Enumerate subdomains for a target domain.

        Invalid targets produce a structured failed collection rather
        than raising an exception to the caller.

        Args:
            target_value:
                Domain to enumerate subdomains for.

        Returns:
            SubdomainCollection containing observations, relationships,
            per-source results, and errors.
        """

        observed_at = utc_now_iso()

        try:
            target = classify_target(target_value)
        except InvalidTargetError as exc:
            logger.warning("Rejected invalid subdomain target: %r (%s)", target_value, exc)
            return self._create_failed_collection(target_value, observed_at, exc)

        logger.info("Starting subdomain enumeration for %s", target.value)

        collection = SubdomainCollection(
            target=target,
            observed_at=observed_at,
            collector=CollectorInfo(version=self.VERSION),
            status=CollectionStatus.SUCCESS,
        )

        # normalized hostname -> accumulated discovery evidence. A dict
        # (not a list) is what makes deduplication-with-provenance simple:
        # the same hostname from a second source appends to the existing
        # entry instead of creating a second one.
        discovered: dict[str, list[DiscoveryEvidence]] = {}

        for source in self.sources:
            logger.info("Running source %s for %s", source.name, target.value)
            self._run_source(source, target.value, collection, discovered, observed_at)

        self._build_observations(collection, discovered)

        if self.config.validate_dns:
            self._validate_observations(collection)

        self._calculate_status(collection)

        logger.info(
            "Completed subdomain enumeration for %s: status=%s observations=%d sources=%d",
            target.value,
            collection.status.value,
            len(collection.observations),
            len(collection.sources),
        )

        return collection

    def _run_source(
        self,
        source: SubdomainSource,
        domain: str,
        collection: SubdomainCollection,
        discovered: dict[str, list[DiscoveryEvidence]],
        observed_at: str,
    ) -> None:
        """
        Run one discovery source and fold its accepted candidates into
        `discovered`. A source failure is recorded structurally and does
        not prevent other sources (or already-discovered candidates)
        from being used.
        """

        try:
            raw_candidates = source.enumerate(domain, timeout=self.config.request_timeout)

        except SourceError as exc:
            logger.warning("Source %s failed for %s: %s", source.name, domain, exc)
            self._record_source_failure(collection, source, "SOURCE_ERROR", str(exc))
            return

        except Exception as exc:  # noqa: BLE001 -- a third-party source must never crash the whole collection
            logger.error("Source %s raised an unexpected error for %s: %s", source.name, domain, exc)
            self._record_source_failure(collection, source, "UNEXPECTED_ERROR", str(exc))
            return

        accepted = 0

        for raw_candidate in raw_candidates:
            hostname = normalize_hostname(raw_candidate.hostname)

            if hostname is None:
                continue

            if not is_in_scope(hostname, domain):
                continue

            evidence = DiscoveryEvidence(
                source=source.name,
                method=source.method,
                observed_at=observed_at,
                source_reference=raw_candidate.source_reference,
            )
            discovered.setdefault(hostname, []).append(evidence)
            accepted += 1

        collection.sources.append(
            SourceResult(
                source=source.name,
                status=SourceStatus.SUCCESS,
                candidate_count=accepted,
            )
        )

    def _record_source_failure(
        self,
        collection: SubdomainCollection,
        source: SubdomainSource,
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
        collection: SubdomainCollection,
        discovered: dict[str, list[DiscoveryEvidence]],
    ) -> None:
        """
        Turn deduplicated discoveries into bounded, ordered observations
        and their graph-ready relationships.

        Sorted rather than insertion-ordered so truncation is
        deterministic -- rerunning the same collection with the same
        max_candidates keeps the same hostnames, not whichever happened
        to be discovered first.
        """

        hostnames_sorted = sorted(discovered.keys())

        collection.candidate_count = len(hostnames_sorted)
        collection.truncated = len(hostnames_sorted) > self.config.max_candidates

        if collection.truncated:
            logger.warning(
                "%s discovered %d candidate hostnames; keeping only the first %d "
                "(see SubdomainCollectorConfig.max_candidates).",
                collection.target.value,
                len(hostnames_sorted),
                self.config.max_candidates,
            )

        bounded_hostnames = hostnames_sorted[: self.config.max_candidates]

        for hostname in bounded_hostnames:
            evidence = discovered[hostname]

            collection.observations.append(
                SubdomainObservation(
                    hostname=hostname,
                    parent_domain=collection.target.value,
                    discovery=evidence,
                )
            )

            collection.related_entities.append(
                EntityRelationship(
                    entity_type="hostname",
                    value=hostname,
                    relationship="discovered_subdomain",
                    source_record=evidence[0].source,
                )
            )

    def _validate_observations(self, collection: SubdomainCollection) -> None:
        """
        Optionally resolve each observation's A/AAAA/CNAME records.

        Bounded implicitly by max_candidates (observations were already
        truncated in _build_observations before this runs) -- validation
        never queries more hostnames than were kept as observations.
        """

        wildcard_ips: set[str] = set()

        if self.config.detect_wildcard:
            wildcard_ips = detect_wildcard_ips(
                collection.target.value,
                nameservers=self.config.nameservers,
                timeout=self.config.dns_timeout,
                lifetime=self.config.dns_lifetime,
            )
            if wildcard_ips:
                logger.warning(
                    "%s appears to use wildcard DNS; validated hostnames matching "
                    "it will be flagged as wildcard matches rather than presented "
                    "as independently confirmed.",
                    collection.target.value,
                )

        for observation in collection.observations:
            status, records = validate_hostname(
                observation.hostname,
                nameservers=self.config.nameservers,
                timeout=self.config.dns_timeout,
                lifetime=self.config.dns_lifetime,
            )

            observation.dns_status = status
            observation.dns_records = records

            if wildcard_ips and any(
                record.value in wildcard_ips for record in records if record.type in ("A", "AAAA")
            ):
                observation.is_wildcard_match = True

    def _create_failed_collection(
        self,
        target_value: str,
        observed_at: str,
        error: InvalidTargetError,
    ) -> SubdomainCollection:
        """
        Create a structured result for an invalid target, matching the
        DNS collector's convention of never raising for bad input.
        """

        return SubdomainCollection(
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
    def _calculate_status(collection: SubdomainCollection) -> None:
        """
        Determine the final collection status from per-source outcomes.

        SUCCESS: every source succeeded.
        PARTIAL: at least one source succeeded and at least one failed.
        FAILED: every source failed (or there were no sources at all).

        Truncation does not affect status -- it is a deliberate,
        logged policy limit, not a failure.
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
