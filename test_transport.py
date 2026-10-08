"""Real loopback HTTP/TLS tests; DNS and external target connections are forbidden."""

import logging
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from socketserver import BaseRequestHandler, TCPServer
from threading import Thread

import pytest

from scanner.core.config import ScanConfig
from scanner.core.errors import LimitReached, RobotsDenied, TLSVerificationError, TransportError
from scanner.core.session import HTTPSession, retry_after_seconds
from scanner.core.target import Target
from scanner.core.transport import TCPTransport, verified_tls_context
from scanner.safety.authorization import ScopeGate
from scanner.safety.budget import ScanControl
from scanner.safety.policy import ScopeError
from scanner.safety.resolver import Resolution
from scanner.safety.state import AuthorizationStore
from tests.lab import LAB_HOST, serve_lab


def make_http(
    state: AuthorizationStore, url: str, config: ScanConfig | None = None, virtual: bool = False
) -> tuple[HTTPSession, ScanControl]:
    """Authorize one named loopback fixture and optionally avoid real retry sleeps."""
    config = config or ScanConfig()
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    scope = ScopeGate(state, resolver=lambda _: Resolution(("127.0.0.1",))).authorize(Target.web(url))
    control = ScanControl(config, clock=lambda: clock[0], sleep=sleep) if virtual else ScanControl(config)
    tcp = TCPTransport(scope, config, control.for_check(100))
    return HTTPSession(tcp, config), control


def test_numeric_pinning_host_cookies_and_proxy_independence(
    state: AuthorizationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No post-approval DNS, proxy/netrc auth, cookie resend or hostname loss."""
    with serve_lab() as lab:
        http, control = make_http(state, lab.url)

        def no_dns(*args: object, **kwargs: object) -> None:
            raise AssertionError("DNS must not run during a transport operation")

        monkeypatch.setattr(socket, "getaddrinfo", no_dns)
        monkeypatch.setenv("HTTP_PROXY", "http://169.254.169.254:80")
        monkeypatch.setenv("ALL_PROXY", "http://169.254.169.254:80")
        first, second = http.request(lab.url), http.request(lab.url)
        assert first.status_code == second.status_code == 200
        assert len(first.header_values("set-cookie")) == 2
        assert all(headers["Host"] == f"{LAB_HOST}:{lab.port}" for _, _, headers in lab.requests)
        assert all("Cookie" not in headers and "Authorization" not in headers for _, _, headers in lab.requests)
        assert control.counts() == {"HTTP": 2, "TCP": 0, "TLS": 0}


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "TRACE", "CONNECT", "get"])
def test_modifying_methods_rejected_before_io(state: AuthorizationStore, method: str) -> None:
    """Reject unsupported verbs before pacing or touching a server."""
    with serve_lab() as lab:
        http, control = make_http(state, lab.url)
        with pytest.raises(ScopeError):
            http.request(lab.url, method)
        assert not lab.requests and sum(control.counts().values()) == 0


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "evil.local"},
        {"Authorization": "secret"},
        {"Cookie": "secret"},
        {"Origin": "https://probe.invalid\r\nInjected: true"},
    ],
)
def test_header_injection_and_credentials_rejected(state: AuthorizationStore, headers: dict[str, str]) -> None:
    """Only allow minimal CORS/accept probe headers without controls."""
    with serve_lab() as lab:
        http, _ = make_http(state, lab.url)
        with pytest.raises(ScopeError):
            http.request(lab.url, headers=headers)
        assert not lab.requests


def test_redirects_scope_hops_and_loops(state: AuthorizationStore) -> None:
    """Follow a permitted relative hop but never contact external redirect destinations."""
    with serve_lab() as lab:
        http, _ = make_http(state, lab.url, ScanConfig(max_redirects=1))
        final = http.request(lab.url + "/redirect", follow_redirects=True)
        assert final.url.endswith("/final") and final.redirect_history == (302,)
        for path in ("offsite", "otherhost", "loop", "chain"):
            response = http.request(lab.url + "/" + path, follow_redirects=True)
            assert response.status_code == 302 and response.redirect_blocked
        assert all("never" not in path for _, path, _ in lab.requests)
        assert http.limitations()


def test_body_caps_compression_and_header_only(state: AuthorizationStore) -> None:
    """Never return more than the cap or silently decompress remote input."""
    with serve_lab() as lab:
        http, _ = make_http(state, lab.url, ScanConfig(max_response_bytes=256))
        oversized = http.request(lab.url + "/large")
        assert len(oversized.body) == 256 and oversized.body_truncated
        compressed = http.request(lab.url + "/compressed")
        assert compressed.body == b"" and compressed.body_unavailable_reason
        header_only = http.request(lab.url + "/compressed", read_body=False)
        assert not header_only.body_unavailable_reason and header_only.status_code == 200
        assert http.request(lab.url, method="HEAD").body == b""
        assert http.request(lab.url, method="OPTIONS").status_code == 200


def test_retry_backoff_is_bounded_and_counted(state: AuthorizationStore) -> None:
    """Recover from 503, cap 429 retries, and reserve each attempt globally."""
    with serve_lab() as lab:
        http, control = make_http(state, lab.url, virtual=True)
        assert http.request(lab.url + "/retry").status_code == 200
        assert lab.retry_count == 3 and control.counts()["HTTP"] == 3
        assert http.request(lab.url + "/busy").status_code == 429
        assert control.counts()["HTTP"] == 7 and http.limitations()


def test_robots_policy_caches_and_blocks(state: AuthorizationStore) -> None:
    """Respect configured disallows; malformed policy is not permission to fetch."""
    with serve_lab() as lab:
        http, _ = make_http(state, lab.url, ScanConfig(respect_robots=True))
        http.request(lab.url + "/allowed")
        with pytest.raises(RobotsDenied):
            http.request(lab.url + "/private")
        http.request(lab.url + "/allowed-again")
        assert sum(path == "/robots.txt" for _, path, _ in lab.requests) == 1
        assert not any(path == "/private" for _, path, _ in lab.requests)


def test_header_limit_and_slow_stream_deadline(state: AuthorizationStore) -> None:
    """A drip-fed response cannot extend the absolute operation timeout indefinitely."""
    with serve_lab() as lab:
        http, _ = make_http(state, lab.url, ScanConfig(timeout=0.15))
        with pytest.raises(TransportError):
            http.request(lab.url + "/oversized_headers")
        started = time.monotonic()
        with pytest.raises(TransportError):
            http.request(lab.url + "/slow")
        assert time.monotonic() - started < 0.8


def test_target_secrets_absent_from_library_debug_logs(
    state: AuthorizationStore, caplog: pytest.LogCaptureFixture
) -> None:
    """Library debug logging cannot expose raw paths/query/header values."""
    with serve_lab() as lab:
        http, _ = make_http(state, lab.url)
        caplog.set_level(logging.DEBUG, logger="urllib3")
        response = http.request(lab.url + "/synthetic-secret-path?token=synthetic-secret-value")
        assert "synthetic-secret" not in caplog.text and "synthetic-secret" not in repr(response)
        logging.getLogger("urllib3.connectionpool").debug("unrelated-client-diagnostic")
        assert "unrelated-client-diagnostic" in caplog.text


def test_tls_sni_hostname_ca_verification_and_downgrade(
    state: AuthorizationStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verified named TLS works on pinned IPs and never creates environment key logs."""
    keylog = tmp_path / "forbidden-keylog.txt"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    with serve_lab(tmp_path) as lab:
        config = ScanConfig(ca_bundle=lab.ca_bundle)
        http, control = make_http(state, lab.url, config)

        def no_dns(*args: object, **kwargs: object) -> None:
            raise AssertionError("TLS must connect using the approved numeric address")

        monkeypatch.setattr(socket, "getaddrinfo", no_dns)
        assert http.request(lab.url).status_code == 200
        observation = http.tcp.inspect_tls(LAB_HOST, lab.port)
        assert observation.protocol in {"TLSv1.2", "TLSv1.3"} and observation.certificate_der
        assert all(name == LAB_HOST for name in lab.sni)
        assert control.counts()["TLS"] == 1
        blocked = http.request(lab.url + "/downgrade", follow_redirects=True)
        assert blocked.redirect_blocked and len(lab.requests) == 2
        wrong_name, _ = make_http(state, lab.url.replace(LAB_HOST, "wrong.local"), config)
        with pytest.raises(TLSVerificationError):
            wrong_name.request(lab.url.replace(LAB_HOST, "wrong.local"))
        untrusted, _ = make_http(state, lab.url)
        with pytest.raises(TLSVerificationError):
            untrusted.request(lab.url)
        assert not keylog.exists() and verified_tls_context(lab.ca_bundle).keylog_filename is None


def test_passive_tcp_banner_and_port_scope(state: AuthorizationStore) -> None:
    """Read an actual loopback banner, then reject an unapproved port before connecting."""

    class Handler(BaseRequestHandler):
        """Emit a fixed public banner and accept no scanner payload."""

        def handle(self) -> None:
            """Return synthetic service text to the connected client."""
            self.request.sendall(b"SSH-2.0-SyntheticFixture\r\n")

    with TCPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            scope = ScopeGate(state).authorize(Target.net("127.0.0.1"), ports=(port,))
            config = ScanConfig()
            control = ScanControl(config)
            tcp = TCPTransport(scope, config, control.for_check(1))
            assert tcp.banner("127.0.0.1", port).startswith(b"SSH-2.0-")
            with pytest.raises(ScopeError):
                tcp.open("127.0.0.1", 1 if port != 1 else 2)
            with pytest.raises(LimitReached):
                tcp.open("127.0.0.1", port)
        finally:
            server.shutdown()
            thread.join(timeout=1)


def test_retry_after_date_and_numeric_limits() -> None:
    """Date/numeric delays remain bounded, and malformed inputs are ignored."""
    now = datetime(2026, 10, 6, tzinfo=timezone.utc)
    assert retry_after_seconds("9999999999") == 30
    assert retry_after_seconds("Tue, 06 Oct 2026 00:00:05 GMT", now) == 5
    assert retry_after_seconds("invalid", now) == 0
    assert retry_after_seconds("-5", now) == 0
    assert retry_after_seconds("9" * 200, now) == 0


def test_stalled_tls_handshake_is_bounded(state: AuthorizationStore) -> None:
    """A TCP peer that never completes TLS cannot indefinitely occupy an HTTP worker."""

    class Handler(BaseRequestHandler):
        """Consume a synthetic ClientHello and deliberately withhold the TLS response."""

        def handle(self) -> None:
            """Keep the fixture peer idle briefly to exercise handshake timeout cleanup."""
            self.request.settimeout(0.5)
            self.request.recv(1)
            time.sleep(0.3)

    with TCPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()
        try:
            url = f"https://{LAB_HOST}:{server.server_address[1]}"
            http, _ = make_http(state, url, ScanConfig(timeout=0.1))
            started = time.monotonic()
            with pytest.raises(TransportError):
                http.request(url)
            assert time.monotonic() - started < 0.5
        finally:
            server.shutdown()
            thread.join(timeout=1)
