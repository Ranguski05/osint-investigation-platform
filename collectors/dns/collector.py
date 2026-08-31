"""
Main orchestration layer for the DNS collector.

The DNSCollector coordinates:

- Target validation
- DNS record collection
- Reverse DNS collection
- Related hostname resolution
- Relationship generation
- Collection status calculation

Low-level DNS operations are handled by DNSResolver.
"""

from __future__ import annotations

from .exceptions import InvalidTargetError
from .models import (
    CollectionError,
    CollectionStatus,
    CollectorInfo,
    DNSCollection,
    DNSCollectorConfig,
    DNSQueryMetadata,
    EntityRelationship,
    Target,
    TargetType,
)
from .resolver import DNSResolver
from .utils import (
    classify_target,
    normalize_dns_name,
    utc_now_iso,
)


class DNSCollector:
    """
    Public interface for DNS collection.

    The rest of the OSINT platform should interact with this class
    rather than directly using DNSResolver.

    Example:

        collector = DNSCollector()
        result = collector.collect("example.com")
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        config: DNSCollectorConfig | None = None,
        *,
        nameservers: list[str] | None = None,
        timeout: float = 3.0,
        lifetime: float = 5.0,
        resolve_related_hosts: bool = True,
    ) -> None:
        """
        Initialize the DNS collector.

        Args:
            config:
                Optional complete DNSCollectorConfig.

            nameservers:
                Optional list of DNS server IP addresses.
                If omitted, the system resolver configuration
                is used.

            timeout:
                Timeout for individual DNS operations.

            lifetime:
                Maximum lifetime allowed for a DNS resolution.

            resolve_related_hosts:
                Whether MX, NS, and CNAME targets should also
                have their A/AAAA records resolved.
        """

        if config is not None:
            self.config = config

        else:
            self.config = DNSCollectorConfig(
                nameservers=nameservers,
                timeout=timeout,
                lifetime=lifetime,
                resolve_related_hosts=resolve_related_hosts,
            )

        if self.config.timeout <= 0:
            raise ValueError(
                "timeout must be greater than zero."
            )

        if self.config.lifetime <= 0:
            raise ValueError(
                "lifetime must be greater than zero."
            )

        if self.config.related_resolution_depth < 0:
            raise ValueError(
                "related_resolution_depth cannot be negative."
            )

        self.resolver = DNSResolver(
            nameservers=self.config.nameservers,
            timeout=self.config.timeout,
            lifetime=self.config.lifetime,
        )

    def collect(
        self,
        target_value: str,
    ) -> DNSCollection:
        """
        Collect DNS information for a target.

        Domains and hostnames receive normal DNS record collection.

        IP addresses receive a reverse DNS/PTR lookup.

        Invalid targets produce a structured failed collection
        rather than raising an exception to the caller.

        Args:
            target_value:
                Domain, hostname, IPv4 address, or IPv6 address.

        Returns:
            DNSCollection containing records, relationships,
            query metadata, and errors.
        """

        observed_at = utc_now_iso()

        try:
            target = classify_target(
                target_value
            )

        except InvalidTargetError as exc:
            return self._create_failed_collection(
                target_value=target_value,
                observed_at=observed_at,
                error=exc,
            )

        collection = DNSCollection(
            target=target,
            observed_at=observed_at,
            collector=CollectorInfo(
                name="dns",
                version=self.VERSION,
            ),
            status=CollectionStatus.SUCCESS,
        )

        if target.type == TargetType.IP:
            self._collect_ptr(
                collection
            )

        else:
            self._collect_domain_records(
                collection
            )

        self._calculate_status(
            collection
        )

        return collection

    def _collect_domain_records(
        self,
        collection: DNSCollection,
    ) -> None:
        """
        Collect configured DNS record types for a domain or hostname.
        """

        target = collection.target.value

        for record_type in self.config.record_types:

            result = self.resolver.query(
                name=target,
                record_type=record_type,
            )

            self._append_query_metadata(
                collection=collection,
                query_type=record_type,
                result=result,
            )

            if result.records:
                collection.records.extend(
                    result.records
                )

            self._append_query_error(
                collection=collection,
                query_type=record_type,
                result=result,
            )

        self._create_relationships(
            collection
        )

        if (
            self.config.resolve_related_hosts
            and self.config.related_resolution_depth > 0
        ):
            self._resolve_related_hosts(
                collection
            )

    def _collect_ptr(
        self,
        collection: DNSCollection,
    ) -> None:
        """
        Perform reverse DNS resolution for an IP address.
        """

        result = self.resolver.reverse_lookup(
            collection.target.value
        )

        self._append_query_metadata(
            collection=collection,
            query_type="PTR",
            result=result,
        )

        if result.records:
            collection.records.extend(
                result.records
            )

        self._append_query_error(
            collection=collection,
            query_type="PTR",
            result=result,
        )

        for record in result.records:

            collection.related_entities.append(
                EntityRelationship(
                    entity_type="hostname",
                    value=record.value,
                    relationship="reverse_resolves_to",
                    source_record="PTR",
                )
            )

    def _resolve_related_hosts(
        self,
        collection: DNSCollection,
    ) -> None:
        """
        Resolve hostnames referenced by MX, NS, and CNAME records.

        Only A and AAAA records are requested for related hosts.

        Resolution is intentionally limited to one logical level.
        Newly discovered hosts are not recursively followed.
        """

        if self.config.related_resolution_depth < 1:
            return

        target_name = normalize_dns_name(
            collection.target.value
        )

        hostnames: set[str] = set()

        for record in collection.records:

            if record.type not in {
                "MX",
                "NS",
                "CNAME",
            }:
                continue

            hostname = normalize_dns_name(
                record.value
            )

            # Ignore empty values.
            if not hostname:
                continue

            # "." represents the DNS root.
            #
            # In particular, a null MX record uses:
            #
            #     MX 0 .
            #
            # The root is not a host that should be resolved.
            if hostname == ".":
                continue

            # Do not resolve the original target again.
            if hostname == target_name:
                continue

            hostnames.add(
                hostname
            )

        for hostname in sorted(hostnames):

            self._resolve_related_hostname(
                collection=collection,
                hostname=hostname,
            )

    def _resolve_related_hostname(
        self,
        collection: DNSCollection,
        hostname: str,
    ) -> None:
        """
        Resolve A and AAAA records for one related hostname.
        """

        for record_type in (
            "A",
            "AAAA",
        ):

            result = self.resolver.query(
                name=hostname,
                record_type=record_type,
            )

            query_type = (
                f"{hostname} {record_type}"
            )

            self._append_query_metadata(
                collection=collection,
                query_type=query_type,
                result=result,
            )

            for record in result.records:

                collection.records.append(
                    record
                )

                collection.related_entities.append(
                    EntityRelationship(
                        entity_type="ip",
                        value=record.value,
                        relationship=(
                            "related_host_resolves_to"
                        ),
                        source_record=record_type,
                    )
                )

            self._append_query_error(
                collection=collection,
                query_type=query_type,
                result=result,
            )

    @staticmethod
    def _create_relationships(
        collection: DNSCollection,
    ) -> None:
        """
        Generate graph-friendly relationships from DNS records.

        These relationships are not stored in a graph database yet.
        They are simply structured observations that the future
        correlation/graph layer can consume.
        """

        for record in collection.records:

            if record.type in {
                "A",
                "AAAA",
            }:

                collection.related_entities.append(
                    EntityRelationship(
                        entity_type="ip",
                        value=record.value,
                        relationship="resolves_to",
                        source_record=record.type,
                    )
                )

            elif record.type == "MX":

                # A null MX record is:
                #
                #     MX 0 .
                #
                # It means the domain does not accept email.
                # Therefore "." must not become a mail_server
                # entity.
                if record.value == ".":
                    continue

                collection.related_entities.append(
                    EntityRelationship(
                        entity_type="mail_server",
                        value=record.value,
                        relationship="mail_server",
                        source_record="MX",
                    )
                )

            elif record.type == "NS":

                collection.related_entities.append(
                    EntityRelationship(
                        entity_type="nameserver",
                        value=record.value,
                        relationship=(
                            "authoritative_nameserver"
                        ),
                        source_record="NS",
                    )
                )

            elif record.type == "CNAME":

                collection.related_entities.append(
                    EntityRelationship(
                        entity_type="hostname",
                        value=record.value,
                        relationship="canonical_name",
                        source_record="CNAME",
                    )
                )

    def _append_query_metadata(
        self,
        collection: DNSCollection,
        query_type: str,
        result,
    ) -> None:
        """
        Store metadata describing an individual DNS query.
        """

        collection.queries.append(
            DNSQueryMetadata(
                query_type=query_type,
                resolver=(
                    self.resolver.resolver_description
                ),
                duration_ms=result.duration_ms,
                status=result.status,
            )
        )

    def _append_query_error(
        self,
        collection: DNSCollection,
        query_type: str,
        result,
    ) -> None:
        """
        Convert a resolver error into a structured collection error.
        """

        if result.error_type is None:
            return

        collection.errors.append(
            CollectionError(
                query_type=query_type,
                error_type=result.error_type,
                message=result.error_message or "",
                resolver=(
                    self.resolver.resolver_description
                ),
            )
        )

    def _create_failed_collection(
        self,
        target_value: str,
        observed_at: str,
        error: InvalidTargetError,
    ) -> DNSCollection:
        """
        Create a structured result for an invalid target.

        Keeping invalid input inside the normal collection schema
        makes the collector easier for the future backend to consume.
        """

        fallback_target = Target(
            value=str(target_value),
            type=TargetType.DOMAIN,
        )

        return DNSCollection(
            target=fallback_target,
            observed_at=observed_at,
            collector=CollectorInfo(
                name="dns",
                version=self.VERSION,
            ),
            status=CollectionStatus.FAILED,
            errors=[
                CollectionError(
                    query_type=None,
                    error_type="INVALID_TARGET",
                    message=str(error),
                    resolver=(
                        self.resolver.resolver_description
                    ),
                )
            ],
        )

    @staticmethod
    def _calculate_status(
        collection: DNSCollection,
    ) -> None:
        """
        Determine the final collection status.

        SUCCESS:
            At least one record was collected and there were
            no errors.

        PARTIAL:
            Some records were collected but one or more queries
            produced errors.

        FAILED:
            No records were collected and at least one error
            occurred.

        PARTIAL is also used when the DNS server returns no useful
        records and no explicit exception was raised.
        """

        if collection.records and collection.errors:
            collection.status = CollectionStatus.PARTIAL

        elif collection.records:
            collection.status = CollectionStatus.SUCCESS

        elif collection.errors:
            collection.status = CollectionStatus.FAILED

        else:
            collection.status = CollectionStatus.PARTIAL