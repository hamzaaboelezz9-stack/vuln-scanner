"""Exact allowlists and publisher-sourced cloud blocks; deny takes precedence."""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlsplit

from scanner.core.target import IPAddress, IPNetwork, normalize_host

MAX_ALLOWLIST_BYTES = 65536
MAX_POLICY_BYTES = 8 * 1024 * 1024
MAX_POLICY_AGE = timedelta(days=7)
MAX_PUBLICATION_AGE = timedelta(days=14)
CLOCK_SKEW = timedelta(minutes=5)
REQUIRED_PROVIDERS = frozenset({"aws", "azure", "google"})
PRIVATE_V4 = tuple(ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
PRIVATE_V6 = ip_network("fc00::/7")
HARD_BLOCKS = tuple(
    ip_network(value)
    for value in (
        "0.0.0.0/8",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "fe80::/10",
        "ff00::/8",
        "2001:db8::/32",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "2002::/16",
        "2001::/32",
        "fd00:ec2::254/128",  # AWS IPv6 instance metadata, blocked even if allowlisted.
        "fd20:ce::254/128",  # Google IPv6 instance metadata.
    )
)


class ScopeError(PermissionError):
    """A requested connection does not satisfy the authorization policy."""


def canonical_ip(value: str) -> IPAddress:
    """Normalize mapped IPv6 to IPv4 so address-family changes cannot bypass rules."""
    address = ip_address(value)
    return getattr(address, "ipv4_mapped", None) or address


def blocked_domain(host: str) -> bool:
    """Block gov/mil labels, including country-qualified government domains."""
    return bool({"gov", "mil"}.intersection(normalize_host(host).split(".")))


def default_local(address: IPAddress) -> bool:
    """Use explicit RFC1918 networks, never the broader is_private property."""
    return address.is_loopback or any(
        address.version == network.version and address in network for network in PRIVATE_V4
    )


def hard_blocked(address: IPAddress) -> bool:
    """Reject metadata, multicast, documentation and translated address ranges."""
    return any(address.version == network.version and address in network for network in HARD_BLOCKS)


@dataclass(frozen=True)
class Allowlist:
    """Immutable exact host/IP/CIDR entries; wildcard matching is unsupported."""

    hosts: frozenset[str] = frozenset()
    networks: tuple[IPNetwork, ...] = ()

    @classmethod
    def from_file(cls, path: Path) -> "Allowlist":
        """Read explicit scope; a missing or malformed supplied file is an error."""
        try:
            with path.open("rb") as handle:
                payload = handle.read(MAX_ALLOWLIST_BYTES + 1)
            if len(payload) > MAX_ALLOWLIST_BYTES:
                raise ScopeError("Allowlist is too large.")
            return cls.from_lines(payload.decode("utf-8").splitlines())
        except (OSError, UnicodeError, ValueError) as error:
            raise ScopeError("Could not read a valid allowlist.") from error

    @classmethod
    def from_lines(cls, lines: list[str]) -> "Allowlist":
        """Parse comments and exact entries, rejecting wildcards and URLs."""
        hosts: set[str] = set()
        networks: list[IPNetwork] = []
        for number, line in enumerate(lines, start=1):
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                if "/" in entry:
                    network = ip_network(entry, strict=True)
                    if network.prefixlen == 0 or getattr(network.network_address, "ipv4_mapped", None):
                        raise ValueError("Overbroad or mapped network.")
                    networks.append(network)
                else:
                    host = normalize_host(entry)
                    try:
                        host = str(canonical_ip(host))
                    except ValueError:
                        # A domain remains an exact domain, not a suffix rule.
                        pass
                    hosts.add(host)
            except ValueError as error:
                raise ScopeError(f"Invalid allowlist entry on line {number}.") from error
        return cls(frozenset(hosts), tuple(networks))

    def contains(self, host: str) -> bool:
        """Match an exact canonical name, exact address or approved network."""
        host = normalize_host(host)
        if host in self.hosts:
            return True
        try:
            address = canonical_ip(host)
        except ValueError:
            return False
        return str(address) in self.hosts or any(
            address.version == network.version and address in network for network in self.networks
        )


def publisher_url(provider: str, value: str) -> bool:
    """Recognize only the configured official provider feeds, without redirects."""
    if provider == "aws":
        return value == "https://ip-ranges.amazonaws.com/ip-ranges.json"
    if provider == "google":
        return value == "https://www.gstatic.com/ipranges/goog.json"
    parsed = urlsplit(value)
    return (
        provider == "azure"
        and parsed.scheme == "https"
        and parsed.netloc == "download.microsoft.com"
        and not parsed.query
        and not parsed.fragment
        and bool(re.fullmatch(r"/download/[A-Za-z0-9/-]+/ServiceTags_Public_[0-9]{8}\.json", parsed.path))
    )


def aware_time(value: str) -> datetime:
    """Require an explicitly timezone-aware ISO timestamp."""
    if not isinstance(value, str):
        raise ValueError("Timestamp must be text.")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.utcoffset() is None:
        raise ValueError("A timezone is required.")
    return result.astimezone(timezone.utc)


@dataclass(frozen=True)
class CloudRangePolicy:
    """Local snapshot with source metadata; hashes document provenance, not signatures."""

    captured_at: datetime
    published_at: tuple[datetime, ...]
    networks: tuple[IPNetwork, ...]

    @classmethod
    def from_file(cls, path: Path) -> "CloudRangePolicy":
        """Validate schema, provider completeness, source locations and CIDRs."""
        try:
            with path.open("rb") as handle:
                payload = handle.read(MAX_POLICY_BYTES + 1)
            if len(payload) > MAX_POLICY_BYTES:
                raise ValueError("Policy is too large.")
            data = json.loads(payload)
            if data["schema"] != "vulnscanner.cloud-policy.v1" or set(data["sources"]) != REQUIRED_PROVIDERS:
                raise ValueError("Incomplete provider policy.")
            captured = aware_time(data["captured_at"])
            published: list[datetime] = []
            networks: list[IPNetwork] = []
            for provider, source in data["sources"].items():
                if not publisher_url(provider, source["url"]) or not re.fullmatch(r"[a-f0-9]{64}", source["sha256"]):
                    raise ValueError("Invalid provider source metadata.")
                published.append(aware_time(source["published_at"]))
                if not source["ranges"]:
                    raise ValueError("Empty provider range list.")
                for value in source["ranges"]:
                    network = ip_network(value, strict=True)
                    if network.prefixlen == 0:
                        raise ValueError("Default routes are not provider ranges.")
                    networks.append(network)
            return cls(captured, tuple(published), tuple(networks))
        except (OSError, UnicodeError, ValueError, TypeError, KeyError, AttributeError) as error:
            raise ScopeError("Cloud-range policy is missing or invalid; public scanning is blocked.") from error

    def require_fresh(self, now: datetime | None = None) -> None:
        """Fail closed on stale, future-dated or incomplete provider metadata."""
        now = now or datetime.now(timezone.utc)
        dates = (self.captured_at, *self.published_at)
        if now.utcoffset() is None or any(date.utcoffset() is None for date in dates):
            raise ScopeError("Policy timestamps must be timezone-aware.")
        if len(self.published_at) != len(REQUIRED_PROVIDERS) or not self.networks:
            raise ScopeError("Incomplete cloud policy.")
        if any(date > now + CLOCK_SKEW for date in dates):
            raise ScopeError("Cloud policy contains future timestamps.")
        if now - self.captured_at > MAX_POLICY_AGE or any(
            now - date > MAX_PUBLICATION_AGE for date in self.published_at
        ):
            raise ScopeError("Cloud policy is stale; refresh it before public scanning.")

    def blocks(self, address: IPAddress) -> bool:
        """Apply provider ranges before any allowlist or private-address exception."""
        return any(address.version == network.version and address in network for network in self.networks)
