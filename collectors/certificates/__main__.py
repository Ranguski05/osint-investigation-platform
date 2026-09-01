"""
Command-line interface for the certificate intelligence collector.

The CLI is intentionally thin, following collectors/dns's and
collectors/subdomains's convention: it parses arguments, configures the
collector, runs the collection, and prints the result.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .collector import CertificateCollector
from .models import CertificateCollection, CertificateCollectorConfig


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="certificate-collector",
        description=(
            "Discover certificates for a target domain via passive "
            "Certificate Transparency search, extracting Subject "
            "Alternative Names (SANs) and certificate metadata."
        ),
    )

    parser.add_argument(
        "target",
        help="Domain to search Certificate Transparency logs for.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the collection result as JSON.",
    )

    parser.add_argument(
        "--max-certificates",
        type=int,
        default=200,
        metavar="N",
        help="Maximum number of deduplicated certificates to keep (default: 200).",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="HTTP request timeout for the Certificate Transparency source (default: 5 seconds).",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose/debug logging.",
    )

    return parser


def configure_logging(verbose: bool) -> None:
    """Configure application logging."""

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main() -> int:
    """
    Run the certificate collector CLI.

    Returns:
        Process exit code.
    """

    parser = build_parser()
    args = parser.parse_args()

    configure_logging(args.verbose)

    if args.max_certificates <= 0:
        parser.error("--max-certificates must be greater than zero.")

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")

    config = CertificateCollectorConfig(
        max_certificates=args.max_certificates,
        request_timeout=args.timeout,
    )

    collector = CertificateCollector(config=config)
    result = collector.collect(args.target)

    if args.json:
        print(json.dumps(result.to_dict(), indent=4))
    else:
        _print_human(result)

    if result.status.value == "failed":
        return 1

    return 0


def _print_human(result: CertificateCollection) -> None:
    """Print a compact, readable summary -- the JSON output remains the canonical structured result."""

    print(f"Target: {result.target.value}")
    print(f"Status: {result.status.value}")
    print(
        f"Certificates discovered: {result.candidate_count}"
        + (" (truncated)" if result.truncated else "")
    )
    print()

    for source in result.sources:
        line = f"  source={source.source} status={source.status.value} certificates={source.candidate_count}"
        if source.error_type:
            line += f" error={source.error_type}: {source.message}"
        print(line)

    print()

    for certificate in result.certificates:
        san_names = ", ".join(
            f"*.{san.name}" if san.is_wildcard else san.name for san in certificate.sans
        )
        print(f"  certificate_id={certificate.certificate_id}  status={certificate.status.value}")
        print(f"    common_name={certificate.common_name}  issuer={certificate.issuer}")
        print(f"    not_before={certificate.not_before}  not_after={certificate.not_after}")
        print(f"    sans=[{san_names}]")

    if result.errors:
        print("\nErrors:")
        for error in result.errors:
            print(f"  {error.query_type}: {error.error_type} - {error.message}")


if __name__ == "__main__":
    sys.exit(main())
