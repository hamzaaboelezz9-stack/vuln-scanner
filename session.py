"""Read-only, bounded HTTP requests with manual redirects and shared backoff."""

import http.client
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from threading import Lock
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import requests
import urllib3

from scanner.core.config import ScanConfig
from scanner.core.errors import RobotsDenied, TransportError
from scanner.core.target import Target, TargetError
from scanner.core.transport import TCPTransport
from scanner.safety.policy import ScopeError
from scanner.safety.probes import reject_private_get
from scanner.safety.rate_limit import MAX_BACKOFF_SECONDS, MAX_RETRIES, backoff_seconds
from scanner.utils.http import SAFE_METHODS, ScopedAdapter, private_http_logging, response_headers

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
RETRY_STATUSES = frozenset({429, 503})
BODY_CHUNK_BYTES = 4096
MAX_REQUEST_HEADERS = 8
ALLOWED_REQUEST_HEADERS = frozenset(
    {"accept", "origin", "access-control-request-method", "access-control-request-headers"}
)
MAX_HEADER_VALUE_BYTES = 512
ROBOTS_PRODUCT = "VulnScanner"
MAX_ROBOTS_BYTES = 64 * 1024


@dataclass(frozen=True)
class HTTPResponse:
    """An in-memory response snapshot; body/header values never enter automatic logs."""

    url: str = field(repr=False)
    status_code: int
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body: bytes = field(repr=False)
    body_truncated: bool = False
    body_unavailable_reason: str = ""
    redirect_history: tuple[int, ...] = ()
    redirect_blocked: str = ""

    def header_values(self, name: str) -> tuple[str, ...]:
        """Read all values without incorrectly joining multiple Set-Cookie headers."""
        return tuple(value for key, value in self.headers if key.lower() == name.lower())

    def header(self, name: str, default: str = "") -> str:
        """Join ordinary repeated headers; use header_values for cookie analysis."""
        values = self.header_values(name)
        return ", ".join(values) if values else default

    def text(self) -> str:
        """Decode the bounded body using its declared charset, safely falling back to UTF-8."""
        match = re.search(r"charset\s*=\s*[\"']?([A-Za-z0-9._-]{1,40})", self.header("content-type"), re.I)
        charset = match.group(1) if match else "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except (LookupError, UnicodeError):
            return self.body.decode("utf-8", errors="replace")


def retry_after_seconds(value: str, now: datetime | None = None) -> float:
    """Parse Retry-After delta/date without allowing remote unbounded delays."""
    if len(value) > 128:
        return 0.0
    if re.fullmatch(r"[0-9]{1,10}", value.strip()):
        return min(float(value), MAX_BACKOFF_SECONDS)
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.utcoffset() is None:
            return 0.0
        return min(max(0.0, (parsed - (now or datetime.now(timezone.utc))).total_seconds()), MAX_BACKOFF_SECONDS)
    except (TypeError, ValueError, OverflowError):
        return 0.0


class HTTPSession:
    """A thread-safe facade creating isolated, anonymous connections for every attempt."""

    def __init__(self, tcp: TCPTransport, config: ScanConfig) -> None:
        """Reuse scope/control, never requests cookies, netrc or environment proxy settings."""
        self.tcp, self.config = tcp, config
        self._robots_lock = Lock()
        self._robots: dict[tuple[str, str, int], RobotFileParser] = {}
        self._limitations_lock = Lock()
        self._limitations: set[str] = set()

    def limitations(self) -> tuple[str, ...]:
        """Return content/redirect limitations for honest engine coverage accounting."""
        with self._limitations_lock:
            return tuple(sorted(self._limitations))

    def _note(self, reason: str) -> None:
        with self._limitations_lock:
            self._limitations.add(reason)

    def _target(self, value: str) -> Target:
        try:
            target = Target.web(value)
        except TargetError as error:
            raise ScopeError("HTTP destination is not a canonical bodyless HTTP(S) URL.") from error
        scheme, host, port = target.origin
        self.tcp.scope.permit(host, port, scheme)
        return target

    def _headers(self, target: Target, supplied: dict[str, str] | None) -> dict[str, str]:
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/json,text/plain;q=0.9,*/*;q=0.5",
            # Do not decompress attacker-controlled input; explicitly request identity.
            "Accept-Encoding": "identity",
            "Connection": "close",
            "Host": urlsplit(target.url).netloc,
        }
        if supplied:
            if len(supplied) > MAX_REQUEST_HEADERS:
                raise ValueError("Too many custom request headers.")
            for name, value in supplied.items():
                if (
                    not isinstance(name, str)
                    or name.lower() not in ALLOWED_REQUEST_HEADERS
                    or not isinstance(value, str)
                    or len(value) > MAX_HEADER_VALUE_BYTES
                    or not value.isascii()
                    or any(ord(character) < 32 or ord(character) == 127 for character in value)
                ):
                    raise ScopeError("Custom header is unsupported or contains invalid characters.")
                headers[name] = value
        return headers

    def _exchange(self, target: Target, method: str, headers: dict[str, str], read_body: bool) -> HTTPResponse:
        scheme, host, port = target.origin
        permit = self.tcp.scope.permit(host, port, scheme)
        prepared = requests.Request(method, target.url, headers=headers).prepare()
        # Requests may normalize paths but must never change the approved authority.
        if self._target(prepared.url).origin != target.origin:
            raise ScopeError("Request preparation changed the authorized origin.")
        self.tcp.budget.begin("HTTP")
        seconds = min(self.config.timeout, self.tcp.budget.control.remaining())
        adapter = ScopedAdapter(self.tcp, permit, scheme, seconds)
        response: requests.Response | None = None
        with private_http_logging():
            try:
                response = adapter.send(prepared)
                self.tcp.budget.control.checkpoint()
                headers_snapshot = response_headers(response)
                if method == "HEAD" or not read_body:
                    return HTTPResponse(target.url, response.status_code, headers_snapshot, b"")
                encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
                if encoding not in {"", "identity"}:
                    return HTTPResponse(
                        target.url,
                        response.status_code,
                        headers_snapshot,
                        b"",
                        body_unavailable_reason="Server sent compressed content despite an identity request; body was not decoded.",
                    )
                body = bytearray()
                maximum = self.config.max_response_bytes
                while len(body) <= maximum:
                    self.tcp.budget.control.checkpoint()
                    chunk = response.raw.read(min(BODY_CHUNK_BYTES, maximum + 1 - len(body)), decode_content=False)
                    if not chunk:
                        break
                    body.extend(chunk)
                self.tcp.budget.control.checkpoint()
                return HTTPResponse(
                    target.url, response.status_code, headers_snapshot, bytes(body[:maximum]), len(body) > maximum
                )
            except (ScopeError, TransportError):
                raise
            except (
                requests.RequestException,
                urllib3.exceptions.HTTPError,
                OSError,
                http.client.HTTPException,
            ) as error:
                raise TransportError("Approved HTTP response could not be read within transport limits.") from error
            finally:
                if response is not None:
                    response.close()
                adapter.close()

    def _attempts(self, target: Target, method: str, headers: dict[str, str], read_body: bool = True) -> HTTPResponse:
        for attempt in range(MAX_RETRIES + 1):
            response = self._exchange(target, method, headers, read_body)
            if response.status_code not in RETRY_STATUSES or attempt == MAX_RETRIES:
                return response
            delay = max(backoff_seconds(attempt), retry_after_seconds(response.header("retry-after")))
            self.tcp.budget.control.limiter.defer(delay)
        raise AssertionError("Finite retry loop did not return.")

    def _robots_allowed(self, target: Target) -> None:
        with self._robots_lock:
            policy = self._robots.get(target.origin)
            if policy is None:
                robots_url = urljoin(target.url, "/robots.txt")
                robots_target = self._target(robots_url)
                response = self._attempts(robots_target, "GET", self._headers(robots_target, None))
                policy = RobotFileParser(robots_url)
                if response.status_code in {404, 410}:
                    policy.parse([])
                elif response.status_code in {401, 403}:
                    policy.parse(["User-agent: *", "Disallow: /"])
                elif (
                    response.status_code == 200
                    and not response.body_truncated
                    and not response.body_unavailable_reason
                    and len(response.body) <= MAX_ROBOTS_BYTES
                ):
                    policy.parse(response.text().splitlines())
                else:
                    raise RobotsDenied("robots.txt could not be interpreted safely; requested path was not fetched.")
                self._robots[target.origin] = policy
        if not policy.can_fetch(ROBOTS_PRODUCT, target.url):
            raise RobotsDenied("robots.txt disallows the requested path.")

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
        read_body: bool = True,
    ) -> HTTPResponse:
        """Fetch in-scope URLs; optionally follow bounded same-host redirects, never downgrades."""
        if method not in SAFE_METHODS or type(follow_redirects) is not bool or type(read_body) is not bool:
            raise ScopeError("Only bodyless GET, HEAD and OPTIONS requests are supported.")
        target = self._target(url)
        history: list[int] = []
        visited = {target.url}
        while True:
            if method == "GET":
                reject_private_get(target.url)
            custom_headers = self._headers(target, headers)
            if self.config.respect_robots:
                self._robots_allowed(target)
            response = self._attempts(target, method, custom_headers, read_body)
            response = replace(response, redirect_history=tuple(history))
            if response.body_truncated:
                self._note("A response body exceeded the byte cap; content coverage is partial.")
            if response.body_unavailable_reason:
                self._note(response.body_unavailable_reason)
            if response.status_code in RETRY_STATUSES:
                self._note("The target remained rate-limited or unavailable after bounded retries.")
            if not follow_redirects or response.status_code not in REDIRECT_STATUSES:
                return response
            locations = response.header_values("location")
            if len(locations) != 1:
                self._note("A redirect could not be followed safely.")
                return replace(response, redirect_blocked="Redirect lacked exactly one Location header.")
            if len(history) >= self.config.max_redirects:
                self._note("Redirect hop limit reached.")
                return replace(response, redirect_blocked="Redirect hop limit reached.")
            try:
                next_target = self._target(urljoin(target.url, locations[0]))
            except (ScopeError, ValueError):
                self._note("An invalid or out-of-scope redirect was not followed.")
                return replace(response, redirect_blocked="Redirect destination is invalid or outside approved scope.")
            if target.origin[0] == "https" and next_target.origin[0] == "http":
                self._note("HTTPS-to-HTTP redirect was not followed.")
                return replace(response, redirect_blocked="HTTPS-to-HTTP redirect was not followed.")
            if next_target.url in visited:
                self._note("Redirect loop detected.")
                return replace(response, redirect_blocked="Redirect loop detected.")
            visited.add(next_target.url)
            history.append(response.status_code)
            target = next_target
