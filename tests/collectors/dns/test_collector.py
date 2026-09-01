"""
Tests for collectors/dns/collector.py.

DNSCollector.resolver is replaced with a MagicMock in every test here, so
these exercise the orchestration logic (relationships, status calculation,
bounding, DNSSEC/PTR opt-ins) without touching the network or DNSResolver's
own dnspython-specific parsing (covered separately in test_resolver.py).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from collectors.dns.collector import DNSCollector
from collectors.dns.models import CollectionStatus, DNSCollectorConfig, DNSRecord, QueryStatus
from collectors.dns.resolver import QueryResult


def success(records: list[DNSRecord]) -> QueryResult:
    return QueryResult(records=records, status=QueryStatus.SUCCESS, duration_ms=1.0)


def failure(error_type: str, status: QueryStatus, message: str = "boom") -> QueryResult:
    return QueryResult(records=[], status=status, error_type=error_type, error_message=message, duration_ms=1.0)


def make_collector(config: DNSCollectorConfig | None = None, **kwargs) -> DNSCollector:
    collector = DNSCollector(config=config, **kwargs)
    collector.resolver = MagicMock()
    collector.resolver.resolver_description = "8.8.8.8"
    return collector


class TestInputValidation:
    def test_malformed_target_returns_failed_collection_not_an_exception(self):
        collector = make_collector()

        result = collector.collect("not a valid host!!")

        assert result.status == CollectionStatus.FAILED
        assert result.errors[0].error_type == "INVALID_TARGET"
        collector.resolver.query.assert_not_called()

    def test_empty_target_returns_failed_collection(self):
        collector = make_collector()

        result = collector.collect("")

        assert result.status == CollectionStatus.FAILED

    def test_url_is_rejected_rather_than_silently_resolved(self):
        collector = make_collector()

        result = collector.collect("https://example.com/path")

        assert result.status == CollectionStatus.FAILED
        collector.resolver.query.assert_not_called()


class TestBasicCollectionAndStatus:
    def test_successful_domain_collection(self):
        collector = make_collector()

        def fake_query(name, record_type):
            if record_type == "A":
                return success([DNSRecord(type="A", name="example.com", value="93.184.216.34", ttl=300)])
            return success([])

        collector.resolver.query.side_effect = fake_query

        result = collector.collect("example.com")

        assert result.status == CollectionStatus.SUCCESS
        assert result.target.value == "example.com"
        assert any(r.type == "A" and r.value == "93.184.216.34" for r in result.records)

    def test_partial_status_preserves_successful_records_alongside_the_failure(self):
        collector = make_collector()

        def fake_query(name, record_type):
            if record_type == "A":
                return success([DNSRecord(type="A", name="example.com", value="1.2.3.4", ttl=300)])
            if record_type == "AAAA":
                return failure("TIMEOUT", QueryStatus.TIMEOUT)
            return success([])

        collector.resolver.query.side_effect = fake_query

        result = collector.collect("example.com")

        assert result.status == CollectionStatus.PARTIAL
        assert any(r.type == "A" for r in result.records)
        assert any(e.error_type == "TIMEOUT" for e in result.errors)

    def test_nxdomain_on_every_query_yields_failed_status(self):
        collector = make_collector()
        collector.resolver.query.side_effect = lambda name, record_type: failure("NXDOMAIN", QueryStatus.NXDOMAIN)

        result = collector.collect("does-not-exist.invalid")

        assert result.status == CollectionStatus.FAILED
        assert result.records == []
        assert len(result.errors) == len(collector.config.record_types)

    def test_one_query_failing_does_not_abort_the_others(self):
        # A fails, AAAA and MX still succeed -- all three must be attempted.
        collector = make_collector()
        seen_types = []

        def fake_query(name, record_type):
            seen_types.append(record_type)
            if record_type == "A":
                return failure("TIMEOUT", QueryStatus.TIMEOUT)
            return success([])

        collector.resolver.query.side_effect = fake_query
        collector.collect("example.com")

        assert set(collector.config.record_types) <= set(seen_types)


class TestRelationshipGeneration:
    def test_a_record_creates_resolves_to_relationship(self):
        collector = make_collector()

        def fake_query(name, record_type):
            if record_type == "A":
                return success([DNSRecord(type="A", name="example.com", value="1.2.3.4", ttl=300)])
            return success([])

        collector.resolver.query.side_effect = fake_query
        result = collector.collect("example.com")

        rel = next(e for e in result.related_entities if e.entity_type == "ip")
        assert rel.value == "1.2.3.4"
        assert rel.relationship == "resolves_to"
        assert rel.source_record == "A"

    def test_ns_record_creates_nameserver_relationship(self):
        collector = make_collector()

        def fake_query(name, record_type):
            if record_type == "NS":
                return success([DNSRecord(type="NS", name="example.com", value="ns1.example.com", ttl=21600)])
            return success([])

        collector.resolver.query.side_effect = fake_query
        result = collector.collect("example.com")

        rel = next(e for e in result.related_entities if e.entity_type == "nameserver")
        assert rel.value == "ns1.example.com"
        assert rel.relationship == "authoritative_nameserver"

    def test_mx_record_creates_mail_server_relationship(self):
        collector = make_collector()

        def fake_query(name, record_type):
            if record_type == "MX":
                return success(
                    [
                        DNSRecord(
                            type="MX",
                            name="example.com",
                            value="mail.example.com",
                            ttl=300,
                            attributes={"priority": 10},
                        )
                    ]
                )
            return success([])

        collector.resolver.query.side_effect = fake_query
        result = collector.collect("example.com")

        rel = next(e for e in result.related_entities if e.entity_type == "mail_server")
        assert rel.value == "mail.example.com"

    def test_null_mx_creates_no_mail_server_entity(self):
        collector = make_collector()

        def fake_query(name, record_type):
            if record_type == "MX":
                return success(
                    [DNSRecord(type="MX", name="example.com", value=".", ttl=300, attributes={"priority": 0})]
                )
            return success([])

        collector.resolver.query.side_effect = fake_query
        result = collector.collect("example.com")

        assert not any(e.entity_type == "mail_server" for e in result.related_entities)
        # The record itself must still be preserved -- only the fake
        # entity is suppressed.
        assert any(r.type == "MX" and r.value == "." for r in result.records)

    def test_cname_creates_canonical_name_relationship(self):
        collector = make_collector()

        def fake_query(name, record_type):
            if record_type == "CNAME":
                return success([DNSRecord(type="CNAME", name="www.example.com", value="example.com", ttl=300)])
            return success([])

        collector.resolver.query.side_effect = fake_query
        result = collector.collect("www.example.com")

        rel = next(e for e in result.related_entities if e.entity_type == "hostname")
        assert rel.relationship == "canonical_name"


class TestRelatedHostResolution:
    def test_ns_hostname_gets_a_and_aaaa_resolved(self):
        collector = make_collector()
        calls: list[tuple[str, str]] = []

        def fake_query(name, record_type):
            calls.append((name, record_type))
            if name == "example.com" and record_type == "NS":
                return success([DNSRecord(type="NS", name="example.com", value="ns1.example.com", ttl=21600)])
            if name == "ns1.example.com" and record_type == "A":
                return success([DNSRecord(type="A", name="ns1.example.com", value="9.9.9.9", ttl=300)])
            return success([])

        collector.resolver.query.side_effect = fake_query
        result = collector.collect("example.com")

        assert ("ns1.example.com", "A") in calls
        assert ("ns1.example.com", "AAAA") in calls
        ip_rel = next(e for e in result.related_entities if e.value == "9.9.9.9")
        assert ip_rel.relationship == "related_host_resolves_to"

    def test_disabling_related_hosts_skips_resolution(self):
        collector = make_collector(config=DNSCollectorConfig(resolve_related_hosts=False))
        calls: list[tuple[str, str]] = []

        def fake_query(name, record_type):
            calls.append((name, record_type))
            if record_type == "NS":
                return success([DNSRecord(type="NS", name="example.com", value="ns1.example.com", ttl=21600)])
            return success([])

        collector.resolver.query.side_effect = fake_query
        collector.collect("example.com")

        assert not any(name == "ns1.example.com" for name, _ in calls)

    def test_max_related_hosts_caps_how_many_are_resolved(self):
        collector = make_collector(config=DNSCollectorConfig(max_related_hosts=1))
        ns_records = [
            DNSRecord(type="NS", name="example.com", value=f"ns{i}.example.com", ttl=21600) for i in range(5)
        ]
        calls: list[tuple[str, str]] = []

        def fake_query(name, record_type):
            calls.append((name, record_type))
            if name == "example.com" and record_type == "NS":
                return success(ns_records)
            return success([])

        collector.resolver.query.side_effect = fake_query
        collector.collect("example.com")

        resolved_hostnames = {name for name, _ in calls if name != "example.com"}
        assert len(resolved_hostnames) == 1

    def test_null_mx_target_is_never_resolved(self):
        collector = make_collector()
        calls: list[tuple[str, str]] = []

        def fake_query(name, record_type):
            calls.append((name, record_type))
            if record_type == "MX":
                return success(
                    [DNSRecord(type="MX", name="example.com", value=".", ttl=300, attributes={"priority": 0})]
                )
            return success([])

        collector.resolver.query.side_effect = fake_query
        collector.collect("example.com")

        assert not any(name == "." for name, _ in calls)


class TestDnssecOptIn:
    def test_disabled_by_default_leaves_dnssec_signed_as_none(self):
        collector = make_collector()
        collector.resolver.query.side_effect = lambda name, record_type: success([])

        result = collector.collect("example.com")

        assert result.dnssec_signed is None
        assert not any(
            call.kwargs.get("record_type") == "DNSKEY" for call in collector.resolver.query.call_args_list
        )

    def test_enabled_and_dnskey_present_is_signed(self):
        collector = make_collector(config=DNSCollectorConfig(include_dnssec=True))

        def fake_query(name, record_type):
            if record_type == "DNSKEY":
                return success(
                    [DNSRecord(type="DNSKEY", name="example.com", value="257 3 8 abc", ttl=3600, attributes={})]
                )
            return success([])

        collector.resolver.query.side_effect = fake_query
        result = collector.collect("example.com")

        assert result.dnssec_signed is True

    def test_enabled_and_no_dnskey_is_not_signed(self):
        collector = make_collector(config=DNSCollectorConfig(include_dnssec=True))
        collector.resolver.query.side_effect = lambda name, record_type: success([])

        result = collector.collect("example.com")

        assert result.dnssec_signed is False


class TestPtrForDiscoveredIps:
    def test_disabled_by_default(self):
        collector = make_collector()

        def fake_query(name, record_type):
            if record_type == "A":
                return success([DNSRecord(type="A", name="example.com", value="1.2.3.4", ttl=300)])
            return success([])

        collector.resolver.query.side_effect = fake_query
        collector.collect("example.com")

        collector.resolver.reverse_lookup.assert_not_called()

    def test_enabled_reverse_resolves_discovered_ips(self):
        collector = make_collector(config=DNSCollectorConfig(resolve_ptr_for_discovered_ips=True))

        def fake_query(name, record_type):
            if record_type == "A":
                return success([DNSRecord(type="A", name="example.com", value="1.2.3.4", ttl=300)])
            return success([])

        collector.resolver.query.side_effect = fake_query
        collector.resolver.reverse_lookup.return_value = success(
            [DNSRecord(type="PTR", name="4.3.2.1.in-addr.arpa", value="host.example.com", ttl=300)]
        )

        result = collector.collect("example.com")

        collector.resolver.reverse_lookup.assert_called_once_with("1.2.3.4")
        assert any(
            e.relationship == "reverse_resolves_to" and e.value == "host.example.com"
            for e in result.related_entities
        )


class TestPtrForIpTarget:
    def test_ip_target_performs_reverse_lookup(self):
        collector = make_collector()
        collector.resolver.reverse_lookup.return_value = success(
            [DNSRecord(type="PTR", name="4.3.2.1.in-addr.arpa", value="host.example.com", ttl=300)]
        )

        result = collector.collect("1.2.3.4")

        collector.resolver.reverse_lookup.assert_called_once_with("1.2.3.4")
        assert result.records[0].type == "PTR"
        assert result.related_entities[0].relationship == "reverse_resolves_to"

    def test_ip_target_that_fails_ptr_is_a_failed_collection(self):
        collector = make_collector()
        collector.resolver.reverse_lookup.return_value = failure("NXDOMAIN", QueryStatus.NXDOMAIN)

        result = collector.collect("1.2.3.4")

        assert result.status == CollectionStatus.FAILED


class TestConfigValidation:
    def test_rejects_negative_max_related_hosts(self):
        with pytest.raises(ValueError):
            DNSCollector(config=DNSCollectorConfig(max_related_hosts=-1))

    def test_rejects_zero_timeout(self):
        with pytest.raises(ValueError):
            DNSCollector(timeout=0)

    def test_rejects_negative_related_resolution_depth(self):
        with pytest.raises(ValueError):
            DNSCollector(config=DNSCollectorConfig(related_resolution_depth=-1))


class TestVersioning:
    def test_collector_info_uses_the_single_sourced_version(self):
        collector = make_collector()
        collector.resolver.query.side_effect = lambda name, record_type: success([])

        result = collector.collect("example.com")

        assert result.collector.version == DNSCollector.VERSION
        assert result.collector.name == "dns"
