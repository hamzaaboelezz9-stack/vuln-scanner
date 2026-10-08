"""Validated network observations; open ports and banners are not exploit findings."""

import re
from dataclasses import dataclass, field
from enum import Enum

from scanner.core.target import validate_port
from scanner.safety.policy import canonical_ip

MAX_NETWORK_BANNER = 4096
MAX_SURFACE_PORTS = 1024
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
VERSION = re.compile(r"[0-9][A-Za-z0-9._-]{0,63}\Z")
CPE = re.compile(
    r"cpe:2\.3:a:[a-z0-9_-]+:[a-z0-9_-]+:[0-9][A-Za-z0-9._-]{0,63}:(?:\*|-|[a-z0-9_-]{1,16}):\*:\*:\*:\*:\*:\*\Z"
)


class PortState(str, Enum):
    """A connection outcome, never a definitive assertion that a host is dead."""

    OPEN = "open"
    REFUSED = "connection-refused"
    TIMEOUT = "no-response"
    UNREACHABLE = "unreachable"
    ERROR = "local-or-transport-error"


class BannerState(str, Enum):
    """Distinguish passive greeting availability from successful TCP connection."""

    NOT_READ = "not-read"
    COMPLETE = "complete-line-or-eof"
    TIMEOUT = "silent-or-incomplete"
    TRUNCATED = "truncated"
    ERROR = "read-error"


@dataclass(frozen=True)
class TCPProbe:
    """Short-lived transport result; raw greeting bytes never enter serialized reports."""

    address: str
    port: int
    state: PortState
    banner_state: BannerState = BannerState.NOT_READ
    banner: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        """Normalize socket outcomes and bound retained in-memory greetings."""
        object.__setattr__(self, "address", str(canonical_ip(self.address)))
        validate_port(self.port)
        object.__setattr__(self, "state", PortState(self.state))
        object.__setattr__(self, "banner_state", BannerState(self.banner_state))
        if not isinstance(self.banner, bytes) or len(self.banner) > MAX_NETWORK_BANNER:
            raise ValueError("Passive greeting exceeds its memory bound.")
        if self.state is not PortState.OPEN and self.banner:
            raise ValueError("A failed TCP connect cannot have a greeting.")


@dataclass(frozen=True)
class ServiceIdentity:
    """Banner-advertised identity; protocol versions never masquerade as software versions."""

    protocol: str
    product: str | None = None
    version: str | None = None
    cpe: str | None = None

    def __post_init__(self) -> None:
        """Allow only constrained identifiers and concrete product CPE queries."""
        if (
            not isinstance(self.protocol, str)
            or not IDENTIFIER.fullmatch(self.protocol)
            or (
                self.product is not None
                and (not isinstance(self.product, str) or not IDENTIFIER.fullmatch(self.product))
            )
        ):
            raise ValueError("Invalid service identity.")
        if self.version is not None and (not isinstance(self.version, str) or not VERSION.fullmatch(self.version)):
            raise ValueError("Invalid advertised version.")
        if self.cpe is not None and (
            not self.product or not self.version or not isinstance(self.cpe, str) or not CPE.fullmatch(self.cpe)
        ):
            raise ValueError("CVE queries require a concrete product and software version.")

    def to_dict(self) -> dict[str, object]:
        """Return minimal identity metadata without any raw banner or claim of authenticity."""
        return {
            "protocol": self.protocol,
            "product": self.product,
            "advertised_version": self.version,
            "cpe_query": self.cpe,
            "identity_verified": False,
        }


@dataclass(frozen=True)
class PortObservation:
    """Immutable shared-survey record safe for deterministic report construction."""

    address: str
    port: int
    state: PortState
    banner_state: BannerState
    service: ServiceIdentity | None = None

    def __post_init__(self) -> None:
        """Reuse the canonical transport validation and reject impossible service records."""
        probe = TCPProbe(self.address, self.port, self.state, self.banner_state)
        object.__setattr__(self, "address", probe.address)
        object.__setattr__(self, "state", probe.state)
        object.__setattr__(self, "banner_state", probe.banner_state)
        if self.service is not None and (
            not isinstance(self.service, ServiceIdentity) or self.state is not PortState.OPEN
        ):
            raise ValueError("Only an open connection can advertise a service.")

    @property
    def endpoint(self) -> str:
        """Format a numeric TCP endpoint with unambiguous IPv6 brackets."""
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"tcp://{host}:{self.port}"

    def to_dict(self) -> dict[str, object]:
        """Export connection and greeting metadata without private content."""
        return {
            "address": self.address,
            "port": self.port,
            "state": self.state.value,
            "banner": self.banner_state.value,
            "service": self.service.to_dict() if self.service else None,
        }
