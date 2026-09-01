"""
Command-line interface for the DNS collector.

The CLI is intentionally thin. It parses arguments, configures the
collector, runs the collection, and prints the structured result.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .collector import DNSCollector
from .models import DNSCollectorConfig


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line argument parser.
    """

    parser = argparse.ArgumentParser(
        prog="dns-collector",
        description=(
            "Collect publicly resolvable DNS information "
            "for a domain, hostname, or IP address."
        ),
    )

    parser.add_argument(
        "target",
        help=(
            "Domain, hostname, or IP address to investigate."
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the collection result as JSON.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        metavar="SECONDS",
        help=(
            "Timeout for an individual DNS operation "
            "(default: 3 seconds)."
        ),
    )

    parser.add_argument(
        "--lifetime",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help=(
            "Maximum lifetime of a DNS resolution "
            "(default: 5 seconds)."
        ),
    )

    parser.add_argument(
        "--nameserver",
        action="append",
        dest="nameservers",
        metavar="IP",
        help=(
            "DNS nameserver to use. Can be specified "
            "multiple times."
        ),
    )

    parser.add_argument(
        "--no-related",
        action="store_true",
        help=(
            "Do not resolve MX, NS, and CNAME hostnames."
        ),
    )

    parser.add_argument(
        "--max-related-hosts",
        type=int,
        default=10,
        metavar="N",
        help=(
            "Maximum number of related hostnames to resolve "
            "(default: 10)."
        ),
    )

    parser.add_argument(
        "--include-dnssec",
        action="store_true",
        help=(
            "Also collect DNSKEY/DS records and report whether "
            "the zone appears signed."
        ),
    )

    parser.add_argument(
        "--resolve-ptr-for-discovered-ips",
        action="store_true",
        help=(
            "Also attempt PTR lookups for IPs discovered via "
            "A/AAAA records, bounded by --max-related-hosts."
        ),
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose/debug logging.",
    )

    return parser


def configure_logging(
    verbose: bool,
) -> None:
    """
    Configure application logging.
    """

    logging.basicConfig(
        level=(
            logging.DEBUG
            if verbose
            else logging.INFO
        ),
        format=(
            "%(asctime)s "
            "%(levelname)s "
            "%(name)s: "
            "%(message)s"
        ),
    )


def main() -> int:
    """
    Run the DNS collector CLI.

    Returns:
        Process exit code.
    """

    parser = build_parser()
    args = parser.parse_args()

    configure_logging(
        args.verbose
    )

    if args.timeout <= 0:
        parser.error(
            "--timeout must be greater than zero."
        )

    if args.lifetime <= 0:
        parser.error(
            "--lifetime must be greater than zero."
        )

    if args.max_related_hosts < 0:
        parser.error(
            "--max-related-hosts cannot be negative."
        )

    config = DNSCollectorConfig(
        nameservers=args.nameservers,
        timeout=args.timeout,
        lifetime=args.lifetime,
        resolve_related_hosts=(
            not args.no_related
        ),
        max_related_hosts=args.max_related_hosts,
        include_dnssec=args.include_dnssec,
        resolve_ptr_for_discovered_ips=(
            args.resolve_ptr_for_discovered_ips
        ),
    )

    collector = DNSCollector(
        config=config
    )

    result = collector.collect(
        args.target
    )

    print(
        json.dumps(
            result.to_dict(),
            indent=4,
        )
    )

    if result.status.value == "failed":
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())