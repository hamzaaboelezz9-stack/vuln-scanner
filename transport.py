"""Numeric-only socket dialing and verified TLS for approved destinations."""

import errno
import socket
import ssl
import time
import warnings
from dataclasses import dataclass, field
from enum import Enum

import requests

from scanner.core.config import ScanConfig
from scanner.core.errors import TLSVerificationError, TransportError
from scanner.core.network import MAX_NETWORK_BANNER, BannerState, PortState, TCPProbe
from scanner.safety.authorization import AuthorizedScope, EndpointPermit
from scanner.safety.budget import CheckBudget
from scanner.safety.io_deadline import IODeadline
from scanner.safety.policy import ScopeError, canonical_ip

MAX_BANNER_BYTES = 4096
LEGACY_CIPHER_POLICY = "DEFAULT:@SECLEVEL=0"
WEAK_CIPHER_POLICY = "aNULL:eNULL:EXPORT:DES:3DES:RC4:@SECLEVEL=0"


def verified_tls_context(ca_bundle: str | None = None) -> ssl.SSLContext:
    """Use OpenSSL validation, TLS 1.2+, and an explicit CA bundle without key logs."""
    # Construct directly: create_default_context may honor SSLKEYLOGFILE and leak TLS keys.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=ca_bundle or requests.certs.where())
    return context


@dataclass(frozen=True)
class TLSObservation:
    """Verified peer metadata kept in memory until a check selects safe evidence."""

    address: str
    port: int
    protocol: str
    cipher: tuple[str, str, int]
    certificate_der: bytes = field(repr=False)
    certificate_verified: bool = True


class TLSProfile(str, Enum):
    """Curated handshake-only profiles; cannot be used by the HTTP adapter."""

    CERTIFICATE_METADATA = "certificate-metadata"
    TLS10 = "tls-1.0"
    TLS11 = "tls-1.1"
    WEAK_CIPHERS = "weak-ciphers"


class TLSProbeStatus(str, Enum):
    """Non-negotiation is not proof that every cipher/protocol combination is disabled."""

    NEGOTIATED = "negotiated"
    NOT_NEGOTIATED = "not-negotiated"
    UNAVAILABLE = "local-profile-unavailable"


@dataclass(frozen=True)
class TLSProbeResult:
    """A constrained diagnostic handshake outcome with no application data."""

    profile: TLSProfile
    status: TLSProbeStatus
    observation: TLSObservation | None = None
    offered_cipher_names: tuple[str, ...] = ()


def diagnostic_tls_context(profile: TLSProfile) -> ssl.SSLContext:
    """Use OpenSSL for explicitly requested public-metadata/legacy handshake probes only."""
    profile = TLSProfile(profile)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # These probes authenticate no application data. CERT_NONE is confined to
    # this function/method, never inherited by verified HTTP requests.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if profile in {TLSProfile.TLS10, TLSProfile.TLS11}:
        version = ssl.TLSVersion.TLSv1 if profile is TLSProfile.TLS10 else ssl.TLSVersion.TLSv1_1
        with warnings.catch_warnings():
            # Deprecated versions are intentionally offered to detect support.
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = context.maximum_version = version
        context.set_ciphers(LEGACY_CIPHER_POLICY)
    elif profile is TLSProfile.WEAK_CIPHERS:
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        # TLS 1.3 suites are not controlled by SSLContext.set_ciphers, so this
        # diagnostic is pinned to TLS 1.2 and only locally available weak suites.
        context.set_ciphers(WEAK_CIPHER_POLICY)
    return context


class TCPTransport:
    """Dial one pinned numeric IP per attempt; no DNS, proxies or raw SYN traffic."""

    def __init__(self, scope: AuthorizedScope, config: ScanConfig, budget: CheckBudget) -> None:
        """Attach immutable scope and the check's shared operation budget."""
        self.scope, self.config, self.budget = scope, config, budget
        self.tls_context = verified_tls_context(config.ca_bundle)

    def _dial(self, permit: EndpointPermit, timeout: float) -> socket.socket:
        # Private entry point for HTTP: its caller has already reserved an HTTP attempt.
        # Revalidate current policy just before connecting; never re-resolve a name.
        current = self.scope.permit(permit.hostname, permit.port)
        address = canonical_ip(current.addresses[0])
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        peer = (str(address), permit.port, 0, 0) if family == socket.AF_INET6 else (str(address), permit.port)
        connection = socket.socket(family, socket.SOCK_STREAM)
        try:
            connection.settimeout(min(timeout, self.budget.control.remaining()))
            connection.connect(peer)
            self.budget.control.checkpoint()
            return connection
        except BaseException:
            # Cleanup on interruption too; re-raise rather than masking KeyboardInterrupt.
            connection.close()
            raise

    def open(self, hostname: str, port: int) -> socket.socket:
        """Open an approved TCP connection; callers must close the returned socket."""
        permit = self.scope.permit(hostname, port)
        self.budget.begin("TCP")
        try:
            return self._dial(permit, self.config.timeout)
        except ScopeError:
            raise
        except OSError as error:
            raise TransportError("Approved TCP connection failed.") from error

    def banner(self, hostname: str, port: int, maximum: int = MAX_BANNER_BYTES) -> bytes:
        """Read a bounded passive banner without sending application payloads."""
        if type(maximum) is not int or not 1 <= maximum <= MAX_BANNER_BYTES:
            raise ValueError("Banner size must be between 1 and 4096 bytes.")
        try:
            with self.open(hostname, port) as connection:
                connection.settimeout(min(self.config.timeout, self.budget.control.remaining()))
                data = connection.recv(maximum)
                self.budget.control.checkpoint()
                return data
        except ScopeError:
            raise
        except OSError as error:
            raise TransportError("Passive banner read failed or timed out.") from error

    def inspect_tls(self, hostname: str, port: int) -> TLSObservation:
        """Perform a verified handshake and return protocol/cipher/certificate metadata."""
        permit = self.scope.permit(hostname, port, "https" if self.scope.origins else None)
        self.budget.begin("TLS")
        try:
            return self._handshake(permit, self.tls_context, True)
        except ScopeError:
            raise
        except ssl.SSLCertVerificationError as error:
            raise TLSVerificationError("TLS certificate verification failed.", error.verify_code) from error
        except ssl.SSLError as error:
            raise TLSVerificationError("TLS negotiation failed without a trusted certificate.") from error
        except OSError as error:
            raise TransportError("Approved TLS connection failed or timed out.") from error

    def _handshake(self, permit: EndpointPermit, context: ssl.SSLContext, verified: bool) -> TLSObservation:
        guard = IODeadline(min(self.config.timeout, self.budget.control.remaining()))
        raw: socket.socket | None = None
        try:
            raw = self._dial(permit, guard.remaining())
            guard.watch(raw)
            raw.settimeout(guard.remaining())
            with context.wrap_socket(raw, server_hostname=permit.hostname, do_handshake_on_connect=False) as connection:
                raw = None  # SSLSocket now owns the original descriptor.
                guard.watch(connection)
                connection.do_handshake()
                self.budget.control.checkpoint()
                certificate, cipher, protocol = (
                    connection.getpeercert(binary_form=True),
                    connection.cipher(),
                    connection.version(),
                )
                if not cipher or not protocol or (verified and not certificate):
                    raise TLSVerificationError("TLS peer did not provide usable certificate metadata.")
                return TLSObservation(permit.addresses[0], permit.port, protocol, cipher, certificate or b"", verified)
        finally:
            if raw is not None:
                raw.close()
            guard.close()

    def probe_tls(self, hostname: str, port: int, profile: TLSProfile) -> TLSProbeResult:
        """Perform one fixed public diagnostic handshake; send no application bytes."""
        profile = TLSProfile(profile)
        permit = self.scope.permit(hostname, port, "https" if self.scope.origins else None)
        try:
            context = diagnostic_tls_context(profile)
        except (ssl.SSLError, ValueError):
            return TLSProbeResult(profile, TLSProbeStatus.UNAVAILABLE)
        offered = tuple(cipher["name"] for cipher in context.get_ciphers() if cipher["protocol"] != "TLSv1.3")
        self.budget.begin("TLS")
        try:
            observation = self._handshake(permit, context, False)
            return TLSProbeResult(profile, TLSProbeStatus.NEGOTIATED, observation, offered)
        except ScopeError:
            raise
        except ssl.SSLError as error:
            local_reasons = {
                "NO_PROTOCOLS_AVAILABLE",
                "NO_CIPHERS_AVAILABLE",
                "UNSUPPORTED_PROTOCOL",
                "LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED",
            }
            status = TLSProbeStatus.UNAVAILABLE if error.reason in local_reasons else TLSProbeStatus.NOT_NEGOTIATED
            return TLSProbeResult(profile, status, offered_cipher_names=offered)
        except OSError as error:
            raise TransportError("Approved diagnostic TLS connection failed or timed out.") from error

    def probe_port(self, hostname: str, port: int, read_banner: bool = True) -> TCPProbe:
        """Connect once, passively read a bounded greeting, and send no application bytes."""
        if type(read_banner) is not bool:
            raise ValueError("read_banner must be a boolean.")
        permit = self.scope.permit(hostname, port)
        self.budget.begin("TCP")
        guard = IODeadline(min(self.config.timeout, self.budget.control.remaining()))
        connection: socket.socket | None = None
        address = permit.addresses[0]
        try:
            try:
                connection = self._dial(permit, guard.remaining())
            except ScopeError:
                raise
            except OSError as error:
                if isinstance(error, TimeoutError) or error.errno == errno.ETIMEDOUT:
                    state = PortState.TIMEOUT
                elif error.errno == errno.ECONNREFUSED:
                    state = PortState.REFUSED
                elif error.errno in {errno.EHOSTUNREACH, errno.ENETUNREACH}:
                    state = PortState.UNREACHABLE
                else:
                    state = PortState.ERROR
                return TCPProbe(address, port, state)
            guard.watch(connection)
            if not read_banner:
                return TCPProbe(address, port, PortState.OPEN)
            banner = bytearray()
            until = time.monotonic() + min(self.config.network_banner_seconds, guard.remaining())
            banner_state = BannerState.TIMEOUT
            while len(banner) <= MAX_NETWORK_BANNER:
                try:
                    self.budget.control.checkpoint()
                    remaining = min(until - time.monotonic(), guard.remaining())
                except TransportError:
                    break  # Preserve a completed TCP handshake even when greeting coverage expires.
                if remaining <= 0:
                    break
                connection.settimeout(remaining)
                try:
                    part = connection.recv(MAX_NETWORK_BANNER + 1 - len(banner))
                except TimeoutError:
                    break
                except OSError:
                    banner_state = BannerState.ERROR
                    break
                if not part:
                    banner_state = BannerState.COMPLETE
                    break
                banner.extend(part)
                if len(banner) > MAX_NETWORK_BANNER:
                    banner_state = BannerState.TRUNCATED
                    break
                if b"\n" in banner:
                    banner_state = BannerState.COMPLETE
                    break
            return TCPProbe(address, port, PortState.OPEN, banner_state, bytes(banner[:MAX_NETWORK_BANNER]))
        finally:
            if connection is not None:
                connection.close()
            guard.close()
