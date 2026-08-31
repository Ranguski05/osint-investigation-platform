"""
DNS resolution layer for the OSINT platform.

This module is responsible for communicating with DNS resolvers and
converting dnspython response objects into normalized DNSRecord objects.

The collector itself should not need to know how dnspython works.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename
import dns.rdatatype

from .models import DNSRecord, QueryStatus
from .utils import normalize_dns_name


@dataclass
class QueryResult:
    """
    Result of a single DNS query.
    """

    records: list[DNSRecord]
    status: QueryStatus

    error_type: str | None = None
    error_message: str | None = None

    duration_ms: float = 0.0


class DNSResolver:
    """
    Thin wrapper around dnspython's resolver.
    """

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 3.0,
        lifetime: float = 5.0,
    ) -> None:
        """
        Configure the DNS resolver.
        """

        if timeout <= 0:
            raise ValueError(
                "timeout must be greater than zero."
            )

        if lifetime <= 0:
            raise ValueError(
                "lifetime must be greater than zero."
            )

        self.resolver = dns.resolver.Resolver(
            configure=True
        )

        if nameservers:
            self.resolver.nameservers = nameservers

        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime

    @property
    def resolver_description(self) -> str:
        """
        Return the configured resolver addresses.
        """

        return ",".join(
            str(nameserver)
            for nameserver in self.resolver.nameservers
        )

    def query(
        self,
        name: str,
        record_type: str,
    ) -> QueryResult:
        """
        Perform a DNS query.
        """

        started = time.perf_counter()

        try:
            answer = self.resolver.resolve(
                name,
                record_type,
                raise_on_no_answer=False,
            )

            duration_ms = (
                time.perf_counter() - started
            ) * 1000

            if answer.rrset is None:
                return QueryResult(
                    records=[],
                    status=QueryStatus.NO_ANSWER,
                    duration_ms=duration_ms,
                )

            records = self._normalize_answer(
                answer,
                record_type,
            )

            return QueryResult(
                records=records,
                status=QueryStatus.SUCCESS,
                duration_ms=duration_ms,
            )

        except dns.resolver.NXDOMAIN as exc:
            return self._create_error_result(
                started=started,
                status=QueryStatus.NXDOMAIN,
                error_type="NXDOMAIN",
                message=(
                    str(exc)
                    or "The queried domain does not exist."
                ),
            )

        except dns.resolver.LifetimeTimeout as exc:
            return self._create_error_result(
                started=started,
                status=QueryStatus.TIMEOUT,
                error_type="TIMEOUT",
                message=(
                    str(exc)
                    or "DNS resolution lifetime exceeded."
                ),
            )

        except dns.exception.Timeout as exc:
            return self._create_error_result(
                started=started,
                status=QueryStatus.TIMEOUT,
                error_type="TIMEOUT",
                message=(
                    str(exc)
                    or "DNS query timed out."
                ),
            )

        except dns.resolver.NoNameservers as exc:
            return self._handle_no_nameservers(
                started=started,
                exception=exc,
            )

        except dns.resolver.NoAnswer as exc:
            return self._create_error_result(
                started=started,
                status=QueryStatus.NO_ANSWER,
                error_type="NO_ANSWER",
                message=(
                    str(exc)
                    or "No DNS answer was returned."
                ),
            )

        except dns.resolver.YXDOMAIN as exc:
            return self._create_error_result(
                started=started,
                status=QueryStatus.ERROR,
                error_type="YXDOMAIN",
                message=(
                    str(exc)
                    or "The DNS name is too long."
                ),
            )

        except dns.exception.DNSException as exc:
            return self._create_error_result(
                started=started,
                status=QueryStatus.ERROR,
                error_type="DNS_ERROR",
                message=(
                    str(exc)
                    or exc.__class__.__name__
                ),
            )

        except OSError as exc:
            return self._create_error_result(
                started=started,
                status=QueryStatus.ERROR,
                error_type="NETWORK_ERROR",
                message=str(exc),
            )

    def reverse_lookup(
        self,
        ip: str,
    ) -> QueryResult:
        """
        Perform a PTR lookup for an IPv4 or IPv6 address.
        """

        try:
            address = ipaddress.ip_address(ip)

        except ValueError:
            return QueryResult(
                records=[],
                status=QueryStatus.ERROR,
                error_type="INVALID_IP",
                error_message=f"Invalid IP address: {ip}",
            )

        reverse_name = dns.reversename.from_address(
            str(address)
        )

        return self.query(
            str(reverse_name),
            "PTR",
        )

    def _normalize_answer(
        self,
        answer: Any,
        record_type: str,
    ) -> list[DNSRecord]:
        """
        Convert a dnspython answer into DNSRecord objects.
        """

        records: list[DNSRecord] = []

        name = normalize_dns_name(
            str(answer.name)
        )

        ttl = answer.rrset.ttl

        for rdata in answer:
            record = self._normalize_rdata(
                name=name,
                ttl=ttl,
                record_type=record_type,
                rdata=rdata,
            )

            records.append(record)

        return records

    def _normalize_rdata(
        self,
        name: str,
        ttl: int,
        record_type: str,
        rdata: Any,
    ) -> DNSRecord:
        """
        Convert one dnspython RDATA object into a DNSRecord.
        """

        attributes: dict[str, Any] = {}

        if record_type == "A":
            value = str(rdata.address)

        elif record_type == "AAAA":
            value = str(rdata.address)

        elif record_type == "CNAME":
            value = normalize_dns_name(
                str(rdata.target)
            )

        elif record_type == "PTR":
            value = normalize_dns_name(
                str(rdata.target)
            )

        elif record_type == "NS":
            value = normalize_dns_name(
                str(rdata.target)
            )

        elif record_type == "MX":
            value = normalize_dns_name(
                str(rdata.exchange)
            )

            attributes["priority"] = rdata.preference

        elif record_type == "TXT":
            value = rdata.to_text()

        elif record_type == "SOA":
            value = normalize_dns_name(
                str(rdata.mname)
            )

            attributes.update(
                {
                    "rname": normalize_dns_name(
                        str(rdata.rname)
                    ),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "minimum": rdata.minimum,
                }
            )

        elif record_type == "CAA":
            value = rdata.to_text()

            attributes.update(
                {
                    "flags": rdata.flags,
                    # dnspython returns tag/value as raw bytes.
                    "tag": rdata.tag.decode(
                        "utf-8", errors="replace"
                    ),
                    "value": rdata.value.decode(
                        "utf-8", errors="replace"
                    ),
                }
            )

        elif record_type == "DNSKEY":
            value = rdata.to_text()

            attributes.update(
                {
                    "flags": rdata.flags,
                    "protocol": rdata.protocol,
                    "algorithm": rdata.algorithm,
                }
            )

        elif record_type == "DS":
            value = rdata.to_text()

            digest = rdata.digest

            if isinstance(digest, bytes):
                digest = digest.hex()

            attributes.update(
                {
                    "key_tag": rdata.key_tag,
                    "algorithm": rdata.algorithm,
                    "digest_type": rdata.digest_type,
                    "digest": str(digest),
                }
            )

        elif record_type == "RRSIG":
            value = rdata.to_text()

            attributes.update(
                {
                    "type_covered": (
                        dns.rdatatype.to_text(
                            rdata.type_covered
                        )
                    ),
                    "algorithm": rdata.algorithm,
                    "labels": rdata.labels,
                    "original_ttl": rdata.original_ttl,
                    "expiration": rdata.expiration,
                    "inception": rdata.inception,
                    "key_tag": rdata.key_tag,
                    "signer": normalize_dns_name(
                        str(rdata.signer)
                    ),
                }
            )

        elif record_type in {"NSEC", "NSEC3"}:
            value = rdata.to_text()

        else:
            value = rdata.to_text()

        return DNSRecord(
            type=record_type,
            name=name,
            value=value,
            ttl=ttl,
            attributes=attributes,
        )

    @staticmethod
    def _create_error_result(
        started: float,
        status: QueryStatus,
        error_type: str,
        message: str,
    ) -> QueryResult:
        """
        Create a QueryResult representing a failed query.
        """

        duration_ms = (
            time.perf_counter() - started
        ) * 1000

        return QueryResult(
            records=[],
            status=status,
            error_type=error_type,
            error_message=message,
            duration_ms=duration_ms,
        )

    def _handle_no_nameservers(
        self,
        started: float,
        exception: dns.resolver.NoNameservers,
    ) -> QueryResult:
        """
        Convert NoNameservers into a useful structured result.
        """

        message = str(exception)
        upper_message = message.upper()

        if "SERVFAIL" in upper_message:
            status = QueryStatus.SERVFAIL
            error_type = "SERVFAIL"

        elif "REFUSED" in upper_message:
            status = QueryStatus.REFUSED
            error_type = "REFUSED"

        else:
            status = QueryStatus.ERROR
            error_type = "NO_NAMESERVERS"

        return self._create_error_result(
            started=started,
            status=status,
            error_type=error_type,
            message=message or error_type,
        )