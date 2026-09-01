"""
Command-line interface for the subdomain enumeration collector.

The CLI is intentionally thin, following collectors/dns's convention: it
parses arguments, configures the collector, runs the collection, and
prints the result.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .collector import SubdomainCollector
from .models import SubdomainCollection, SubdomainCollectorConfig
from .sources.base import SubdomainSource
from .sources.crtsh import CrtShSource
from .sources.dns_bruteforce import DNSBruteforceSource, parse_wordlist


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line argument parser.
    """

    parser = argparse.ArgumentParser(
        prog="subdomain-collector",
        description=(
            "Discover subdomains of a target domain, passively via "
            "Certificate Transparency and optionally via active, "
            "bounded DNS wordlist enumeration (--bruteforce)."
        ),
    )

    parser.add_argument(
        "target",
        help="Domain to enumerate subdomains for.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the collection result as JSON.",
    )

    parser.add_argument(
        "--max-candidates",
        type=int,
        default=200,
        metavar="N",
        help=(
            "Maximum number of discovered candidate hostnames "
            "to keep (default: 200)."
        ),
    )

    parser.add_argument(
        "--validate-dns",
        action="store_true",
        help=(
            "Attempt A/AAAA/CNAME resolution for each discovered "
            "hostname."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help=(
            "HTTP request timeout for discovery sources "
            "(default: 5 seconds)."
        ),
    )

    parser.add_argument(
        "--dns-timeout",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help=(
            "Timeout for an individual DNS validation query "
            "(default: 2 seconds)."
        ),
    )

    parser.add_argument(
        "--dns-lifetime",
        type=float,
        default=3.0,
        metavar="SECONDS",
        help=(
            "Maximum lifetime of a DNS validation resolution "
            "(default: 3 seconds)."
        ),
    )

    parser.add_argument(
        "--nameserver",
        action="append",
        dest="nameservers",
        metavar="IP",
        help=(
            "DNS nameserver to use for validation. Can be "
            "specified multiple times."
        ),
    )

    parser.add_argument(
        "--no-wildcard-detection",
        action="store_true",
        help=(
            "Skip the wildcard-DNS probe performed before "
            "validation."
        ),
    )

    parser.add_argument(
        "--bruteforce",
        action="store_true",
        help=(
            "Also discover subdomains via bounded, active DNS wordlist "
            "enumeration, alongside the default Certificate Transparency "
            "source."
        ),
    )

    parser.add_argument(
        "--wordlist",
        type=str,
        metavar="PATH",
        help=(
            "Path to a custom wordlist file, one word per line "
            "(default: a small built-in list). Only used with "
            "--bruteforce."
        ),
    )

    parser.add_argument(
        "--bruteforce-max-candidates",
        type=int,
        default=500,
        metavar="N",
        help=(
            "Maximum number of wordlist entries to test "
            "(default: 500)."
        ),
    )

    parser.add_argument(
        "--bruteforce-concurrency",
        type=int,
        default=5,
        metavar="N",
        help=(
            "Maximum number of concurrent DNS queries during wordlist "
            "enumeration (default: 5)."
        ),
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose/debug logging.",
    )

    return parser


def configure_logging(verbose: bool) -> None:
    """
    Configure application logging.
    """

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main() -> int:
    """
    Run the subdomain collector CLI.

    Returns:
        Process exit code.
    """

    parser = build_parser()
    args = parser.parse_args()

    configure_logging(args.verbose)

    if args.max_candidates <= 0:
        parser.error("--max-candidates must be greater than zero.")

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")

    if args.dns_timeout <= 0:
        parser.error("--dns-timeout must be greater than zero.")

    if args.dns_lifetime <= 0:
        parser.error("--dns-lifetime must be greater than zero.")

    if args.bruteforce_max_candidates <= 0:
        parser.error("--bruteforce-max-candidates must be greater than zero.")

    if args.bruteforce_concurrency <= 0:
        parser.error("--bruteforce-concurrency must be greater than zero.")

    if args.wordlist and not args.bruteforce:
        parser.error("--wordlist requires --bruteforce.")

    config = SubdomainCollectorConfig(
        max_candidates=args.max_candidates,
        validate_dns=args.validate_dns,
        request_timeout=args.timeout,
        dns_timeout=args.dns_timeout,
        dns_lifetime=args.dns_lifetime,
        nameservers=args.nameservers,
        detect_wildcard=not args.no_wildcard_detection,
    )

    sources: list[SubdomainSource] = [CrtShSource()]

    if args.bruteforce:
        wordlist = None
        if args.wordlist:
            try:
                with open(args.wordlist, "r", encoding="utf-8") as handle:
                    wordlist = parse_wordlist(handle.read())
            except OSError as exc:
                parser.error(f"Could not read --wordlist file: {exc}")

        sources.append(
            DNSBruteforceSource(
                wordlist,
                nameservers=args.nameservers,
                dns_lifetime=args.dns_lifetime,
                concurrency=args.bruteforce_concurrency,
                max_words=args.bruteforce_max_candidates,
                detect_wildcard=not args.no_wildcard_detection,
            )
        )

    collector = SubdomainCollector(config=config, sources=sources)
    result = collector.collect(args.target)

    if args.json:
        print(json.dumps(result.to_dict(), indent=4))
    else:
        _print_human(result)

    if result.status.value == "failed":
        return 1

    return 0


def _print_human(result: SubdomainCollection) -> None:
    """
    Print a compact, readable summary -- the JSON output remains the
    canonical structured result for scripting/the backend.
    """

    print(f"Target: {result.target.value}")
    print(f"Status: {result.status.value}")
    print(
        f"Candidates discovered: {result.candidate_count}"
        + (" (truncated)" if result.truncated else "")
    )
    print()

    for source in result.sources:
        line = (
            f"  source={source.source} type={source.source_type.value} "
            f"status={source.status.value} candidates={source.candidate_count}"
        )
        if source.error_type:
            line += f" error={source.error_type}: {source.message}"
        print(line)

    print()

    for observation in result.observations:
        sources = ",".join(sorted({evidence.source for evidence in observation.discovery}))
        line = f"  {observation.hostname}  [{sources}]  dns={observation.dns_status.value}"
        if observation.is_wildcard_match:
            line += "  (wildcard match)"
        print(line)

    if result.errors:
        print("\nErrors:")
        for error in result.errors:
            print(f"  {error.query_type}: {error.error_type} - {error.message}")


if __name__ == "__main__":
    sys.exit(main())
