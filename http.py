"""A requests adapter with numeric dialing, bounded headers and absolute I/O timeouts."""

import http.client
import logging
import socket
import ssl
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, BinaryIO, Iterator
from urllib.parse import urlsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection

from scanner.core.errors import TLSVerificationError, TransportError
from scanner.core.target import Target
from scanner.core.transport import TCPTransport
from scanner.safety.authorization import EndpointPermit
from scanner.safety.io_deadline import IODeadline
from scanner.safety.policy import ScopeError

MAX_HEADER_BYTES = 32 * 1024
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_PRIVATE_IO: ContextVar[bool] = ContextVar("vulnscanner_private_http_io", default=False)


class _TargetLogFilter(logging.Filter):
    """Suppress library URL/header diagnostics only inside this scanner's HTTP work."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Allow unrelated HTTP clients to retain their normal logging behavior."""
        return not _PRIVATE_IO.get()


for _logger_name in (
    "urllib3.connection",
    "urllib3.connectionpool",
    "urllib3.response",
    "urllib3.util.retry",
    "urllib3.util.ssl_",
    "requests",
):
    logging.getLogger(_logger_name).addFilter(_TargetLogFilter())


@contextmanager
def private_http_logging() -> Iterator[None]:
    """Avoid secret-bearing library debug/warning text without changing global log levels."""
    token = _PRIVATE_IO.set(True)
    try:
        yield
    finally:
        _PRIVATE_IO.reset(token)


class _HeaderReader:
    """Cap aggregate status/header bytes before the stdlib allocates parsed headers."""

    def __init__(self, source: BinaryIO) -> None:
        """Wrap an existing buffered stream without taking ownership of its body."""
        self.source, self.remaining = source, MAX_HEADER_BYTES

    def readline(self, maximum: int = -1) -> bytes:
        """Read at most the remaining header allowance plus one overflow byte."""
        limit = self.remaining + 1 if maximum < 0 else min(maximum, self.remaining + 1)
        line = self.source.readline(limit)
        self.remaining -= len(line)
        if self.remaining < 0:
            raise http.client.HTTPException("Response headers exceed the configured limit.")
        return line


class _BoundedHTTPResponse(http.client.HTTPResponse):
    """Retain the stdlib parser while bounding its header input."""

    def begin(self) -> None:
        """Apply the byte cap only during header parsing, then restore body I/O."""
        original = self.fp
        if original is None:
            raise http.client.HTTPException("Response has no readable stream.")
        self.fp = _HeaderReader(original)
        try:
            super().begin()
        finally:
            self.fp = original


class ScopedAdapter(HTTPAdapter):
    """Single-use requests adapter; no proxy, ambient credentials or DNS lookup path."""

    def __init__(self, tcp: TCPTransport, permit: EndpointPermit, scheme: str, seconds: float) -> None:
        """Construct an isolated one-connection pool using a scope-bound connection class."""
        super().__init__(max_retries=0)
        self._tcp, self._permit, self._scheme = tcp, permit, scheme
        self._guard = IODeadline(seconds)
        self._sent = False
        guard = self._guard

        class PinnedHTTPConnection(HTTPConnection):
            """Connect to numeric scope addresses while keeping the original Host name."""

            response_class = _BoundedHTTPResponse

            def _new_conn(self) -> socket.socket:
                connection = tcp._dial(permit, guard.remaining())
                guard.watch(connection)
                return connection

        class PinnedHTTPSConnection(HTTPSConnection):
            """Preserve hostname verification and SNI over the numeric-only socket."""

            response_class = _BoundedHTTPResponse

            def _new_conn(self) -> socket.socket:
                connection = tcp._dial(permit, guard.remaining())
                guard.watch(connection)
                connection.settimeout(guard.remaining())
                return connection

            def connect(self) -> None:
                """Let urllib3/OpenSSL authenticate the peer, then watch the TLS socket."""
                super().connect()
                if self.sock is not None:
                    guard.watch(self.sock)

        if scheme == "https":
            self._pool = urllib3.HTTPSConnectionPool(
                permit.hostname,
                permit.port,
                ssl_context=tcp.tls_context,
                server_hostname=permit.hostname,
                assert_hostname=permit.hostname,
                cert_reqs=ssl.CERT_REQUIRED,
                maxsize=1,
                block=True,
            )
            self._pool.ConnectionCls = PinnedHTTPSConnection
        else:
            self._pool = urllib3.HTTPConnectionPool(permit.hostname, permit.port, maxsize=1, block=True)
            self._pool.ConnectionCls = PinnedHTTPConnection
        self._seconds = seconds

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = True,
        timeout: float | None = None,
        verify: bool | str = True,
        cert: object = None,
        proxies: dict[str, str] | None = None,
    ) -> requests.Response:
        """Send exactly one read-only request, with library retries and redirects disabled."""
        if self._sent or verify is not True or cert is not None or proxies:
            raise ScopeError("Transport reuse, alternate trust settings and proxies are forbidden.")
        if request.method not in SAFE_METHODS or request.body is not None or request.url is None:
            raise ScopeError("Only bodyless GET, HEAD and OPTIONS are permitted.")
        parsed = Target.web(request.url)
        if parsed.origin != (self._scheme, self._permit.hostname, self._permit.port):
            raise ScopeError("Prepared request changed the approved origin.")
        if request.headers.get("Host") != urlsplit(parsed.url).netloc:
            raise ScopeError("HTTP Host must match the approved URL authority.")
        if any(name.lower() in {"authorization", "proxy-authorization", "cookie"} for name in request.headers):
            raise ScopeError("Anonymous transports do not accept authentication state.")
        self._tcp.scope.permit(self._permit.hostname, self._permit.port, self._scheme)
        self._sent = True
        try:
            response = self._pool.urlopen(
                request.method,
                request.path_url,
                headers=dict(request.headers),
                redirect=False,
                retries=False,
                preload_content=False,
                decode_content=False,
                timeout=urllib3.Timeout(total=self._seconds, connect=self._seconds, read=self._seconds),
            )
            return self.build_response(request, response)
        except (ScopeError, TransportError):
            raise
        except (urllib3.exceptions.SSLError, ssl.SSLError) as error:
            raise TLSVerificationError("TLS certificate validation or negotiation failed.") from error
        except (urllib3.exceptions.HTTPError, OSError, http.client.HTTPException) as error:
            raise TransportError("Approved HTTP operation failed or exceeded transport limits.") from error

    def close(self) -> None:
        """Close response sockets, timers and all adapter pools on every exit path."""
        self._guard.close()
        self._pool.close()
        super().close()


def response_headers(response: requests.Response) -> tuple[tuple[str, str], ...]:
    """Preserve repeated headers, especially independent Set-Cookie attributes."""
    raw: Any = response.raw.headers
    return tuple((name, value) for name in raw for value in raw.getlist(name))
