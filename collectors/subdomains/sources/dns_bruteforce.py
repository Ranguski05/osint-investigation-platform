"""
Active DNS wordlist enumeration source.

Unlike CrtShSource (passive: observes existing public Certificate
Transparency data, never contacts the target), this source is ACTIVE: it
builds candidate hostnames from a wordlist (`word.domain`) and sends DNS
queries directly to find out which ones exist. Discovery and existence
checking are the same operation here, so this module reuses
`dns_validation.validate_hostname` (the same narrow, independent DNS
check the collector's optional post-discovery validation step uses)
rather than adding a second DNS implementation.
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

from ..dns_validation import detect_wildcard_ips, validate_hostname
from ..models import DnsValidationStatus, SourceType
from .base import RawCandidate, SubdomainSource

logger = logging.getLogger(__name__)

# A single DNS label: letters/digits, internal hyphens, 1-63 characters.
# Defined independently of utils.py's HOSTNAME_PATTERN (a wordlist entry
# is one label, not a dotted hostname) -- see dns_validation.py's
# docstring for why a little duplication is an accepted tradeoff here.
_WORD_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Small, curated set of common infrastructure names. Deliberately not
# exhaustive -- this source demonstrates active discovery and gives the
# platform a second discovery path, not maximum coverage (see module
# docstring in collector.py and the project's "do not overengineer"
# instruction). A larger or organization-specific list can be supplied
# via the `wordlist` constructor argument or the CLI's --wordlist file.
DEFAULT_WORDLIST: list[str] = [
    "www", "api", "mail", "smtp", "imap", "pop",
    "dev", "development", "test", "testing", "staging", "stage",
    "prod", "production",
    "admin", "portal", "login", "auth",
    "app", "apps", "dashboard",
    "blog", "docs", "support", "status",
    "cdn", "static", "assets", "media",
    "vpn", "remote", "gateway",
    "git", "gitlab", "jenkins", "jira", "confluence",
    "internal", "intranet",
]


def parse_wordlist(text: str) -> list[str]:
    """
    Parse a wordlist file's contents into a clean, deduplicated list of
    DNS labels for use as `DNSBruteforceSource(wordlist=...)`.

    Blank lines are skipped. Each remaining line is stripped and
    lowercased; anything that is not a single valid DNS label is
    silently dropped -- a malformed entry should not abort enumeration,
    the same way an unparseable certificate SAN doesn't abort crt.sh's
    source (see utils.normalize_hostname).
    """

    return _prepare_words(text.splitlines())


def _prepare_words(raw_words: Iterable[str]) -> list[str]:
    words: dict[str, None] = {}

    for raw in raw_words:
        if not isinstance(raw, str):
            continue

        word = raw.strip().lower()

        if not word or not _WORD_PATTERN.fullmatch(word):
            continue

        words.setdefault(word, None)

    return list(words.keys())


class DNSBruteforceSource(SubdomainSource):
    """
    Discovers candidate hostnames by testing a bounded wordlist against
    the target domain via lightweight DNS existence checks.

    Bounded by design:
      - at most `max_words` wordlist entries are tested (deterministic:
        sorted, then truncated, with a WARNING log on truncation);
      - at most `concurrency` DNS queries are outstanding at once, via a
        bounded ThreadPoolExecutor;
      - only A/AAAA/CNAME are queried per candidate (no full DNS
        characterization -- that remains the DNS collector's job).

    Wildcard handling (v1, documented limitation): before testing
    candidates, this source probes for wildcard DNS on the target domain
    (reusing dns_validation.detect_wildcard_ips). Any candidate whose
    resolved A/AAAA values are entirely explained by the wildcard's own
    response is treated as wildcard noise and excluded from the returned
    candidates -- it never becomes an observation or a graph node. This
    is a conservative simplification: a wildcard-matching candidate is
    dropped rather than kept-and-flagged, since flagging only makes sense
    once an observation already exists, and creating an observation for
    a hostname nobody intentionally configured is exactly the "fake
    subdomain" outcome this feature must avoid. Each suppression is
    logged at WARNING with a count; a structured per-candidate wildcard
    field on the source's own output is not implemented in v1.
    """

    name = "dns_bruteforce"
    method = "wordlist"
    source_type = SourceType.ACTIVE

    def __init__(
        self,
        wordlist: list[str] | None = None,
        *,
        nameservers: list[str] | None = None,
        dns_lifetime: float = 3.0,
        concurrency: int = 5,
        max_words: int = 500,
        detect_wildcard: bool = True,
    ) -> None:
        """
        Args:
            wordlist: Words to test as `word.domain`. Defaults to
                DEFAULT_WORDLIST. Normalized (lowercased, deduped,
                validated as single DNS labels) regardless of source.
            nameservers: DNS servers to query. None uses the system
                resolver configuration.
            dns_lifetime: Overall dnspython resolution lifetime per
                query. The per-attempt timeout is supplied by the
                collector via `enumerate(timeout=...)`
                (SubdomainCollectorConfig.request_timeout), reused here
                as the DNS per-query timeout rather than introducing a
                second timeout concept.
            concurrency: Maximum number of DNS queries outstanding at
                once. Conservative by default -- see module docstring.
            max_words: Upper bound on how many wordlist entries are
                tested, even if a much larger custom wordlist is
                supplied. Truncation is deterministic and logged.
            detect_wildcard: Probe for wildcard DNS before testing
                candidates.
        """

        if concurrency <= 0:
            raise ValueError("concurrency must be greater than zero.")

        if max_words <= 0:
            raise ValueError("max_words must be greater than zero.")

        self._raw_wordlist = wordlist if wordlist is not None else DEFAULT_WORDLIST
        self.nameservers = nameservers
        self.dns_lifetime = dns_lifetime
        self.concurrency = concurrency
        self.max_words = max_words
        self.detect_wildcard = detect_wildcard

    def enumerate(self, domain: str, *, timeout: float) -> list[RawCandidate]:
        words = _prepare_words(self._raw_wordlist)
        words.sort()

        if len(words) > self.max_words:
            logger.warning(
                "dns_bruteforce wordlist for %s has %d entries; testing only "
                "the first %d (see DNSBruteforceSource max_words).",
                domain,
                len(words),
                self.max_words,
            )
        words = words[: self.max_words]

        if not words:
            return []

        logger.info(
            "dns_bruteforce starting for %s: %d candidate word(s), concurrency=%d",
            domain,
            len(words),
            self.concurrency,
        )

        wildcard_ips: set[str] = set()
        if self.detect_wildcard:
            wildcard_ips = detect_wildcard_ips(
                domain,
                nameservers=self.nameservers,
                timeout=timeout,
                lifetime=self.dns_lifetime,
            )
            if wildcard_ips:
                logger.warning(
                    "%s appears to use wildcard DNS; dns_bruteforce candidates "
                    "that only resolve because of it will be suppressed, not "
                    "reported as discoveries.",
                    domain,
                )

        candidates: list[RawCandidate] = []
        suppressed = 0

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            future_to_word = {
                pool.submit(
                    validate_hostname,
                    f"{word}.{domain}",
                    nameservers=self.nameservers,
                    timeout=timeout,
                    lifetime=self.dns_lifetime,
                ): word
                for word in words
            }

            for future in as_completed(future_to_word):
                word = future_to_word[future]
                hostname = f"{word}.{domain}"

                try:
                    status, records = future.result()
                except Exception as exc:  # noqa: BLE001 -- one candidate's failure must not abort enumeration
                    logger.debug("dns_bruteforce check failed for %s: %s", hostname, exc)
                    continue

                if status != DnsValidationStatus.RESOLVED:
                    continue

                if wildcard_ips:
                    resolved_ips = {record.value for record in records if record.type in ("A", "AAAA")}
                    if resolved_ips and resolved_ips <= wildcard_ips:
                        suppressed += 1
                        continue

                candidates.append(RawCandidate(hostname=hostname, source_reference=word))

        if suppressed:
            logger.warning(
                "dns_bruteforce suppressed %d wildcard-only match(es) for %s.",
                suppressed,
                domain,
            )

        logger.info(
            "dns_bruteforce completed for %s: %d discovered out of %d tested",
            domain,
            len(candidates),
            len(words),
        )

        return candidates
