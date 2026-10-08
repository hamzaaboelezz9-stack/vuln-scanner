"""Configurable HTTP/TLS security fixtures; every listener is ephemeral loopback."""

import ssl
import warnings
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Callable, Iterator
from urllib.parse import parse_qsl, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tests.lab import LAB_HOST


@dataclass(frozen=True)
class Request:
    """Synthetic request metadata used only by tests, never by published scan reports."""

    method: str
    path: str
    query: tuple[tuple[str, str], ...]
    headers: dict[str, str]

    def value(self, name: str) -> str:
        """Return one fixture query value, preserving the request's original order."""
        return next((value for key, value in self.query if key == name), "")


@dataclass(frozen=True)
class Reply:
    """Fixed status, headers and synthetic content for a route."""

    status: int = 200
    body: bytes = b"<html><title>Owned test fixture</title></html>"
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html; charset=utf-8"),)


Route = Reply | Callable[[Request], Reply]


@dataclass
class WebLab:
    """Fixture routing and observations; no external or production traffic is retained."""

    routes: dict[str, Route] = field(default_factory=dict)
    requests: list[Request] = field(default_factory=list)
    default: Reply = field(default_factory=lambda: Reply(404, b"not found", (("Content-Type", "text/plain"),)))
    port: int = 0
    scheme: str = "http"
    ca_bundle: str | None = None
    sni: list[str | None] = field(default_factory=list)

    @property
    def url(self) -> str:
        """Provide a hostname pinned to loopback by test authorization fixtures."""
        return f"{self.scheme}://{LAB_HOST}:{self.port}"


def issue_certificate(directory: Path, expired: bool = False, not_yet: bool = False) -> tuple[Path, Path, Path]:
    """Create an ephemeral CA and a named leaf with controllable validity dates."""
    now = datetime.now(timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Web rule fixture CA")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, LAB_HOST)])
    start = now + timedelta(hours=1) if not_yet else now - timedelta(days=2)
    end = now - timedelta(hours=1) if expired else now + timedelta(days=90)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(root_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(LAB_HOST)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    ca, cert, private = directory / "rule-ca.pem", directory / "rule-leaf.pem", directory / "rule-key.pem"
    ca.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    private.chmod(0o600)
    return ca, cert, private


@contextmanager
def serve_web_lab(
    directory: Path | None = None,
    expired: bool = False,
    not_yet: bool = False,
    tls_version: ssl.TLSVersion | None = None,
    cipher_policy: str | None = None,
) -> Iterator[WebLab]:
    """Serve synthetic routes and optional TLS; never bind beyond 127.0.0.1."""
    lab = WebLab(scheme="https" if directory else "http")

    class Handler(BaseHTTPRequestHandler):
        """Dispatch synthetic GET/HEAD/OPTIONS; no modifying methods are implemented."""

        def handle(self) -> None:
            """Treat early close after diagnostic handshakes as an expected fixture event."""
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

        def log_message(self, format: str, *args: object) -> None:
            """Disable raw request logging in fixture processes."""

        def do_GET(self) -> None:
            """Record synthetic metadata and serve a deterministic fixture route."""
            parsed = urlsplit(self.path)
            request = Request(
                self.command, parsed.path, tuple(parse_qsl(parsed.query, keep_blank_values=True)), dict(self.headers)
            )
            lab.requests.append(request)
            route = lab.routes.get(parsed.path, lab.default)
            reply = route(request) if callable(route) else route
            self.send_response_only(reply.status)
            for name, value in reply.headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(reply.body)))
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(reply.body)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass  # Header-only and bounded-content checks close early.

        def do_HEAD(self) -> None:
            """Return equivalent metadata without a response body."""
            self.do_GET()

        def do_OPTIONS(self) -> None:
            """Exercise advertisement/preflight handlers without a write request."""
            self.do_GET()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    lab.port = server.server_address[1]
    if directory:
        ca, certificate, private = issue_certificate(directory, expired, not_yet)
        lab.ca_bundle = str(ca)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, private)
        if tls_version is not None:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = context.maximum_version = tls_version
        if cipher_policy:
            context.set_ciphers(cipher_policy)

        def observe_sni(connection: ssl.SSLSocket, hostname: str | None, context: ssl.SSLContext) -> None:
            lab.sni.append(hostname)

        context.set_servername_callback(observe_sni)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
