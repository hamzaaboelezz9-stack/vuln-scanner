"""Approve a bounded immutable scope; never connect to target services here."""

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Callable
from uuid import UUID, uuid4

from scanner.core.target import DEFAULT_PORTS, ScanMode, Target, normalize_host, validate_port
from scanner.safety.policy import (
    PRIVATE_V6,
    Allowlist,
    CloudRangePolicy,
    ScopeError,
    blocked_domain,
    canonical_ip,
    default_local,
    hard_blocked,
)
from scanner.safety.resolver import DNSResolver, Resolution
from scanner.safety.state import AuthorizationStore

DEFAULT_MAX_HOSTS = 256
MAX_HOST_BUDGET = 4096


def _check_addresses(
    host: str, addresses: tuple[str, ...], allowlist: Allowlist, cloud: CloudRangePolicy | None, public_permission: bool
) -> None:
    try:
        canonical_ip(host)
        named_allowed = False
    except ValueError:
        named_allowed = allowlist.contains(host)
    for value in addresses:
        address = canonical_ip(value)
        if hard_blocked(address) or (cloud and cloud.blocks(address)):
            raise ScopeError("Target resolves into a hard-blocked address range.")
        if default_local(address):
            continue
        if address.version == 6 and address in PRIVATE_V6:
            if not (named_allowed or allowlist.contains(str(address))):
                raise ScopeError("IPv6 private networks require an explicit allowlist entry.")
            continue
        if not address.is_global:
            raise ScopeError("Special-purpose or reserved addresses are not scan targets.")
        if not public_permission or not (named_allowed or allowlist.contains(str(address))):
            raise ScopeError("Public targets require an allowlist entry and --i-have-permission.")
        if cloud is None:
            raise ScopeError("A cloud-range policy is required for public targets.")
        cloud.require_fresh()


@dataclass(frozen=True)
class EndpointPermit:
    """Permit numeric peers while preserving the original hostname for HTTP Host and TLS SNI."""

    hostname: str
    port: int
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class AuthorizedScope:
    """One authorized scan with pinned DNS and immutable connection constraints."""

    scan_id: UUID
    target: Target
    addresses: tuple[str, ...]
    ports: tuple[int, ...]
    origins: tuple[tuple[str, str, int], ...]
    allowlist: Allowlist
    cloud: CloudRangePolicy | None
    public_permission: bool

    def permit(self, hostname: str, port: int, scheme: str | None = None) -> EndpointPermit:
        """Validate every destination; never resolve the hostname again after approval."""
        hostname = normalize_host(hostname)
        validate_port(port)
        if blocked_domain(hostname) or port not in self.ports:
            raise ScopeError("Connection falls outside the authorized ports or domain policy.")
        if self.target.mode is ScanMode.WEB:
            if hostname != self.target.hostname or (
                scheme is not None and (scheme, hostname, port) not in self.origins
            ):
                raise ScopeError("Cross-origin connection is outside the authorized web scope.")
            addresses = self.addresses
        elif self.target.network is None and hostname == self.target.hostname:
            addresses = self.addresses
        else:
            try:
                address = str(canonical_ip(hostname))
            except ValueError as error:
                raise ScopeError("Network connections require an approved numeric address.") from error
            if address not in self.addresses:
                raise ScopeError("Address is outside the authorized network scope.")
            addresses = (address,)
        _check_addresses(self.target.hostname, addresses, self.allowlist, self.cloud, self.public_permission)
        return EndpointPermit(hostname, port, addresses)


class ScopeGate:
    """Require legal acknowledgment, validate scope and record every authorization attempt."""

    def __init__(
        self,
        state: AuthorizationStore,
        allowlist: Allowlist | None = None,
        cloud: CloudRangePolicy | None = None,
        resolver: Callable[[str], Resolution] | None = None,
        max_hosts: int = DEFAULT_MAX_HOSTS,
    ) -> None:
        """Inject resolution for tests and enforce a cap before CIDR expansion."""
        if type(max_hosts) is not int or not 1 <= max_hosts <= MAX_HOST_BUDGET:
            raise ValueError("Host budget must be an integer between 1 and 4096.")
        self.state = state
        self.allowlist = allowlist or Allowlist()
        self.cloud = cloud
        self.resolver = resolver or DNSResolver()
        self.max_hosts = max_hosts

    def authorize(
        self, target: Target, public_permission: bool = False, ports: tuple[int, ...] = ()
    ) -> AuthorizedScope:
        """Approve and audit one scan; DNS occurs only after the saved acknowledgment."""
        scan_id = uuid4()
        acknowledged = False
        try:
            if type(public_permission) is not bool:
                raise ScopeError("Public permission must be an explicit boolean.")
            acknowledged = self.state.acknowledged()
            if not acknowledged:
                raise ScopeError("First-run legal acknowledgment is required before resolution.")
            if blocked_domain(target.hostname):
                raise ScopeError("Government and military domains are hard-blocked.")
            if target.network:
                if target.network.num_addresses > self.max_hosts:
                    raise ScopeError("CIDR exceeds the configured host budget.")
                if getattr(target.network.network_address, "ipv4_mapped", None):
                    raise ScopeError("Use an IPv4 CIDR instead of a mapped IPv6 CIDR.")
                addresses = tuple(str(address) for address in target.network.hosts())
            else:
                try:
                    ip_address(target.hostname)
                    is_numeric = True
                except ValueError:
                    is_numeric = False
                if (
                    not is_numeric
                    and target.hostname != "localhost"
                    and not target.hostname.endswith(".local")
                    and not self.allowlist.contains(target.hostname)
                ):
                    raise ScopeError("Named targets require .local, localhost or an exact allowlist entry.")
                resolution = self.resolver(target.hostname)
                if any(blocked_domain(alias) for alias in resolution.aliases):
                    raise ScopeError("A DNS alias points to a hard-blocked government or military domain.")
                addresses = resolution.addresses
                if len(addresses) > self.max_hosts:
                    raise ScopeError("DNS answers exceed the host budget.")
                if target.hostname == "localhost" and any(not canonical_ip(value).is_loopback for value in addresses):
                    raise ScopeError("localhost must resolve exclusively to loopback addresses.")
                if target.hostname.endswith(".local") and any(
                    not default_local(canonical_ip(value)) for value in addresses
                ):
                    raise ScopeError(".local names must resolve exclusively to default local addresses.")
            _check_addresses(target.hostname, addresses, self.allowlist, self.cloud, public_permission)
            origins: tuple[tuple[str, str, int], ...] = ()
            if target.mode is ScanMode.WEB:
                scheme, host, port = target.origin
                other_scheme = "http" if scheme == "https" else "https"
                other_port = DEFAULT_PORTS[other_scheme] if port == DEFAULT_PORTS[scheme] else port
                origins = (target.origin, (other_scheme, host, other_port))
                approved_ports = tuple(sorted({port, other_port}))
            else:
                if not ports:
                    raise ScopeError("Network authorization requires explicitly selected ports.")
                approved_ports = tuple(sorted({validate_port(port) for port in ports}))
            scope = AuthorizedScope(
                scan_id, target, addresses, approved_ports, origins, self.allowlist, self.cloud, public_permission
            )
            self.state.record(scan_id, target.display, "approved", public_permission, acknowledged)
            return scope
        except (ScopeError, ValueError) as error:
            self.state.record(scan_id, target.display, "blocked", public_permission is True, acknowledged, str(error))
            raise ScopeError(str(error)) from error
