"""Ephemeral HTTP/TLS fixtures bound exclusively to IPv4 loopback."""

import gzip
import ssl
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Iterator
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

LAB_HOST = "fixture.local"
LARGE_BODY_BYTES = 8192


@dataclass
class Lab:
    """Only synthetic fixture requests are retained for test assertions."""

    port: int = 0
    scheme: str = "http"
    ca_bundle: str | None = None
    requests: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)
    sni: list[str | None] = field(default_factory=list)
    robots: bytes = b"User-agent: *\nDisallow: /private\n"
    retry_count: int = 0

    @property
    def url(self) -> str:
        """Return the named origin whose DNS will be injected by the scope fixture."""
        return f"{self.scheme}://{LAB_HOST}:{self.port}"


def _tls_files(directory: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ephemeral test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, LAB_HOST)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(LAB_HOST)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, certificate_path, key_path = directory / "ca.pem", directory / "server.pem", directory / "server-key.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    key_path.chmod(0o600)
    return ca_path, certificate_path, key_path


@contextmanager
def serve_lab(directory: Path | None = None) -> Iterator[Lab]:
    """Serve fixed non-vulnerability fixtures; optionally authenticate using an ephemeral CA."""
    lab = Lab(scheme="https" if directory else "http")

    class Handler(BaseHTTPRequestHandler):
        """Implement deterministic routes; do not emit request logs from tests."""

        def log_message(self, format: str, *args: object) -> None:
            """Keep synthetic query strings out of test output."""

        def do_GET(self) -> None:
            """Serve redirects, limits, retries and synthetic text for assertions."""
            lab.requests.append((self.command, self.path, dict(self.headers)))
            path = urlsplit(self.path).path
            status, body = 200, b"<html><title>Local transport fixture</title></html>"
            extra: list[tuple[str, str]] = []
            if path == "/redirect":
                status, extra = 302, [("Location", "/final")]
            elif path == "/offsite":
                status, extra = 302, [("Location", "http://169.254.169.254/never")]
            elif path == "/otherhost":
                status, extra = 302, [("Location", f"http://other.local:{lab.port}/never")]
            elif path == "/downgrade":
                status, extra = 302, [("Location", f"http://{LAB_HOST}:{lab.port}/never")]
            elif path == "/loop":
                status, extra = 302, [("Location", "/loop")]
            elif path == "/chain":
                status, extra = 302, [("Location", "/redirect")]
            elif path == "/large":
                body = b"L" * LARGE_BODY_BYTES
            elif path == "/compressed":
                body, extra = gzip.compress(b"Z" * LARGE_BODY_BYTES), [("Content-Encoding", "gzip")]
            elif path == "/oversized_headers":
                extra = [("X-Oversized", "H" * 40000)]
            elif path == "/retry":
                lab.retry_count += 1
                status = 503 if lab.retry_count <= 2 else 200
                extra = [("Retry-After", "0")]
            elif path == "/busy":
                status, extra = 429, [("Retry-After", "0")]
            elif path == "/robots.txt":
                body = lab.robots
            elif path == "/slow":
                body = b"S" * 100
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "fixture_a=synthetic; HttpOnly; SameSite=Lax")
            self.send_header("Set-Cookie", "fixture_b=synthetic; Secure; SameSite=Strict")
            for key, value in extra:
                self.send_header(key, value)
            self.end_headers()
            try:
                if self.command == "HEAD":
                    return
                if path == "/slow":
                    for byte in body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.04)
                else:
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass  # Limit tests intentionally close response sockets early.

        def do_HEAD(self) -> None:
            """Reuse route headers without emitting a response body."""
            self.do_GET()

        def do_OPTIONS(self) -> None:
            """Exercise read-only OPTIONS transport without invoking modifying methods."""
            self.do_GET()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    lab.port = server.server_address[1]
    if directory:
        ca, certificate, key = _tls_files(directory)
        lab.ca_bundle = str(ca)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)

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
