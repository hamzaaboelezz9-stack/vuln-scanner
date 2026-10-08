"""Bounded DNS resolution with alias inspection; transports must use returned IPs."""

import math
import time
from dataclasses import dataclass

import dns.exception
import dns.rdatatype
import dns.resolver

from scanner.core.target import normalize_host
from scanner.safety.policy import ScopeError, canonical_ip

DNS_TIMEOUT = 3.0
MAX_DNS_ADDRESSES = 32
MAX_DNS_NAMES = 32


@dataclass(frozen=True)
class Resolution:
    """One bounded DNS snapshot with canonical numeric addresses and alias names."""

    addresses: tuple[str, ...]
    aliases: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Reject empty or oversized resolutions and normalize mapped addresses."""
        if not self.addresses or len(self.addresses) > MAX_DNS_ADDRESSES or len(self.aliases) > MAX_DNS_NAMES:
            raise ScopeError("DNS answer is empty or exceeds the safety budget.")
        object.__setattr__(self, "addresses", tuple(sorted({str(canonical_ip(value)) for value in self.addresses})))
        object.__setattr__(self, "aliases", tuple(sorted({normalize_host(value) for value in self.aliases})))


class DNSResolver:
    """Resolve A/AAAA without search suffixes and inspect CNAME/DNAME records."""

    def __init__(self, timeout: float = DNS_TIMEOUT) -> None:
        """Set an aggregate lookup deadline rather than a timeout per record type."""
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("DNS timeout must be positive and finite.")
        self.timeout = timeout

    def __call__(self, host: str) -> Resolution:
        """Return a pin-ready snapshot, with no target service connections."""
        host = normalize_host(host)
        try:
            return Resolution((str(canonical_ip(host)),))
        except ValueError:
            if host == "localhost":
                return Resolution(("127.0.0.1", "::1"))
        addresses: set[str] = set()
        aliases: set[str] = {host}
        deadline = time.monotonic() + self.timeout
        try:
            resolver = dns.resolver.Resolver()
            for kind in ("A", "AAAA"):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ScopeError("DNS resolution deadline exceeded.")
                answer = resolver.resolve(host, kind, search=False, lifetime=remaining, raise_on_no_answer=False)
                aliases.add(answer.canonical_name.to_text())
                for rrset in answer.response.answer:
                    aliases.add(rrset.name.to_text())
                    if rrset.rdtype in (dns.rdatatype.CNAME, dns.rdatatype.DNAME):
                        aliases.update(record.target.to_text() for record in rrset)
                if answer.rrset is not None:
                    addresses.update(record.address for record in answer)
                if len(addresses) > MAX_DNS_ADDRESSES or len(aliases) > MAX_DNS_NAMES:
                    raise ScopeError("DNS answer exceeds the safety budget.")
            return Resolution(tuple(addresses), tuple(aliases))
        except ScopeError:
            raise
        except (dns.exception.DNSException, OSError) as error:
            raise ScopeError("DNS resolution failed; no scan connection is permitted.") from error
