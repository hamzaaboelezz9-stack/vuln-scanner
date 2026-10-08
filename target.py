"""Canonical parsing: never rely on URL parsing alone for validation."""

import re
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from urllib.parse import urlsplit, urlunsplit

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network
MAX_TARGET_LENGTH = 4096
MAX_PORT = 65535
DEFAULT_PORTS = {"http": 80, "https": 443}
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class TargetError(ValueError):
    """An input cannot be unambiguously interpreted as a target."""


class ScanMode(str, Enum):
    """Supported assessment modes."""

    WEB = "web"
    NETWORK = "net"


def normalize_host(value: str) -> str:
    """Normalize an IP or IDNA hostname and reject alternate numeric IP forms."""
    if not isinstance(value, str) or not value or len(value) > MAX_TARGET_LENGTH:
        raise TargetError("A hostname is required.")
    if any(ord(char) <= 32 or ord(char) == 127 for char in value):
        raise TargetError("Whitespace and control characters are not allowed.")
    if any(char in value for char in "%\\/@?#[]"):
        raise TargetError("Encoded hosts, scoped IPv6 and URL syntax are not allowed.")
    host = value[:-1] if value.endswith(".") else value
    try:
        return str(ip_address(host))
    except ValueError:
        # OS resolvers may interpret these as integer, octal or shortened IPs.
        if ":" in host or re.fullmatch(r"[0-9.]+", host):
            raise TargetError("Use a canonical IPv4 or IPv6 address.") from None
        if any(label.lower().startswith("0x") for label in host.split(".")):
            raise TargetError("Hexadecimal address-like hosts are not allowed.")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise TargetError("Invalid internationalized hostname.") from error
    if len(host) > 253 or any(not DNS_LABEL.fullmatch(label) for label in host.split(".")):
        raise TargetError("Invalid DNS hostname.")
    return host


def validate_port(port: int) -> int:
    """Require an actual integer TCP port, excluding bool and out-of-range values."""
    if type(port) is not int or not 1 <= port <= MAX_PORT:
        raise TargetError("Ports must be integers between 1 and 65535.")
    return port


@dataclass(frozen=True)
class Target:
    """Immutable canonical target; construction performs all syntax validation."""

    mode: ScanMode
    value: str = field(repr=False)
    hostname: str = field(init=False)
    port: int | None = field(init=False, default=None)
    url: str | None = field(init=False, default=None, repr=False)
    network: IPNetwork | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        """Validate even direct construction, so factory methods cannot be bypassed."""
        try:
            object.__setattr__(self, "mode", ScanMode(self.mode))
        except ValueError as error:
            raise TargetError("Unknown scan mode.") from error
        if not isinstance(self.value, str) or not 1 <= len(self.value) <= MAX_TARGET_LENGTH:
            raise TargetError("Target length must be between 1 and 4096 characters.")
        if any(ord(char) <= 32 or ord(char) == 127 for char in self.value):
            raise TargetError("Targets must not contain whitespace or control characters.")
        if "\\" in self.value:
            raise TargetError("Backslashes are not allowed in targets.")
        if self.mode is ScanMode.NETWORK:
            if "/" in self.value:
                try:
                    network = ip_network(self.value, strict=True)
                except ValueError as error:
                    raise TargetError("Use a canonical CIDR with no host bits set.") from error
                object.__setattr__(self, "network", network)
                object.__setattr__(self, "hostname", str(network.network_address))
            else:
                object.__setattr__(self, "hostname", normalize_host(self.value))
            return
        try:
            parsed = urlsplit(self.value)
            if parsed.scheme not in DEFAULT_PORTS or not parsed.hostname:
                raise TargetError("Web targets require an http:// or https:// URL.")
            if parsed.username is not None or parsed.password is not None or parsed.fragment:
                raise TargetError("URL credentials and fragments are not allowed.")
            if parsed.netloc.endswith(":"):
                raise TargetError("An empty port is not allowed.")
            hostname = normalize_host(parsed.hostname)
            port = validate_port(parsed.port or DEFAULT_PORTS[parsed.scheme])
            # Reject explicit :0, which must not silently become a default port.
            if parsed.port == 0:
                raise TargetError("Port zero is not allowed.")
        except TargetError:
            raise
        except ValueError as error:
            raise TargetError("Malformed web URL or invalid port.") from error
        authority = f"[{hostname}]" if ":" in hostname else hostname
        if port != DEFAULT_PORTS[parsed.scheme]:
            authority += f":{port}"
        url = urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, ""))
        object.__setattr__(self, "hostname", hostname)
        object.__setattr__(self, "port", port)
        object.__setattr__(self, "url", url)

    @classmethod
    def web(cls, value: str) -> "Target":
        """Parse an absolute HTTP(S) URL."""
        return cls(ScanMode.WEB, value)

    @classmethod
    def net(cls, value: str) -> "Target":
        """Parse an IP, canonical CIDR or hostname."""
        return cls(ScanMode.NETWORK, value)

    @property
    def origin(self) -> tuple[str, str, int]:
        """Return a normalized web origin, excluding path and query."""
        if self.url is None or self.port is None:
            raise TargetError("Network targets have no web origin.")
        return urlsplit(self.url).scheme, self.hostname, self.port

    @property
    def display(self) -> str:
        """Return an audit-safe identifier without URL query values or paths."""
        if self.url:
            scheme, host, port = self.origin
            host = f"[{host}]" if ":" in host else host
            return f"{scheme}://{host}:{port}"
        return str(self.network) if self.network else self.hostname
