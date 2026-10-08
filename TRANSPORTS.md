# Transport and engine API

The core engine and transports underpin the implemented Phase 4 web and network checks.
The original transport diagnostic remains deliberately separate from detection.
See [web rules](WEB_CHECKS.md) for confidence, boundaries and check selection.

## Configuration

`ScanConfig.load(Path("config.yaml"), overrides={"workers": 4})` reads at most
64 KiB of safe UTF-8 YAML, with nesting capped at eight levels. Overrides are applied last. Unknown settings, duplicate
keys, anchors, aliases, arbitrary Python constructors and incorrect types fail.
Permission switches cannot be stored in YAML; they must be passed explicitly at
runtime. Custom user agents must retain scanner identification.

| Setting | Default | Accepted range or meaning |
| --- | --- | --- |
| workers | 10 | 1–64 concurrent check workers. |
| rate_limit | 10 | 0.1–100 attempts/sec; above 10 requires aggressive permission. |
| timeout | 10 seconds | 0.05–60 seconds per transport operation. |
| max_hosts | 256 | 1–4096; the engine also honors the gate's tighter cap. |
| max_operations | 5000 | 1–200000 reserved attempts for the whole scan. |
| scan_seconds | 600 | 0.05–3600 seconds, measured with a monotonic clock. |
| max_response_bytes | 262144 | 256–1048576 retained body bytes. |
| max_redirects | 3 | 0–5 followed hops per request. |
| checks | null | All registered checks for the selected mode, or distinct names. |
| ca_bundle | null | Requests' CA bundle, or an operator-supplied PEM CA file. |
| respect_robots | false | Conservative opt-in robots.txt rules. |
| weak_tls_probes | true | Isolated fixed legacy/cipher handshakes; no application data. |
| tls_expiry_days | 30 | Renewal window, 1–365 days. |
| network_banner_seconds | 0.5 | Passive read window, 0.05–5 seconds within operation/scan deadline. |
| cve_cache | null | Private prepopulated local NVD cache directory; never auto-fetches. |
| traversal_canary_path/token | null | Paired strictly constrained public fixture, never a private file. |

No setting disables certificate or hostname verification. A private lab with a
locally issued certificate should supply its CA bundle. HTTP requires no CA
on the wire, but the engine validates its trust configuration before scheduling.

## HTTP interface

`context.http.request(url, method="GET", headers=None, follow_redirects=False,
read_body=True)` returns `HTTPResponse`. Only bodyless GET, HEAD and OPTIONS are
accepted. Supported custom headers are Accept, Origin,
Access-Control-Request-Method and Access-Control-Request-Headers. Host, cookies,
Authorization, proxy settings and request bodies cannot be supplied.

The returned snapshot provides `status_code`, `header(name)`,
`header_values(name)`, `body`, `text()`, `body_truncated`,
`body_unavailable_reason`, `redirect_history` and `redirect_blocked`. Multiple
Set-Cookie headers remain independent. URL, headers and body are excluded from
the snapshot's representation. Checks must still select minimal evidence;
reading a body is not authorization to publish it.

Each attempt creates an isolated requests adapter and urllib3 pool. Its
connection class overrides numeric dialing, while urllib3 handles HTTP framing
and OpenSSL handles TLS. The URL hostname is preserved for Host, SNI and
certificate authentication. There is no Requests Session, automatic cookie
reuse, netrc lookup, environment proxy lookup or shared mutable connection pool.
This is deliberately simpler than sharing a requests.Session across threads.

One approved address is selected deterministically: the first address in the
immutable scope. A failed address is reported as incomplete coverage; there is
no silent multi-address fallback or unbounded connection fan-out. A new HTTP
request is a new counted connection attempt, including failures and retries.

Response status and headers share a 32 KiB aggregate parser cap. Bodies stream
with a cap-plus-one probe so truncation is distinguishable from an exact-size
body. Accept-Encoding is identity. If the server nevertheless compresses its
response, the body is not decompressed and content coverage is incomplete.
Header-only checks use `read_body=False` and remain independent of this limit.

An absolute watchdog closes HTTP and standalone TLS sockets after the smaller of the operation
timeout and remaining scan lifetime. This prevents slow header/body drips from
indefinitely renewing a per-read timeout. TLS handshakes also have an OpenSSL socket timeout. Every response, pool and watchdog is closed on exit.

429 and 503 responses receive at most three retries: four total attempts.
Backoff is shared across workers and grows 1, 2, then 4 seconds. Retry-After
delta/date values are respected up to 30 seconds; the scan deadline remains
authoritative. Requests already in flight are not recalled by a new backoff.
No connection failures or other HTTP statuses are automatically retried.

Redirects are inspected manually. Every destination is validated before
connection. Only approved origins on the original hostname may be followed;
cross-host redirects, loops, hop overflow, malformed locations and HTTPS-to-HTTP
downgrades stop with a coverage reason. By default redirects are not followed,
which supports open-redirect detection without contacting the destination.

With robots enabled, each check caches policy per approved origin. 404/410
allow paths; 401/403 deny paths. Only an untruncated identity-encoded 200 body
up to 64 KiB is parsed. Unreadable, redirected or otherwise unsupported policy
blocks the requested path. robots.txt discovery itself still uses the scope,
rate and operation controls. Robots rules do not establish legal authorization.

## TCP and TLS interface

- `context.tcp.open(hostname, port)` returns a socket the caller must close.
- `context.tcp.banner(hostname, port, maximum=4096)` reads a passive bounded banner
  and closes the connection without sending application data.
- `context.tcp.inspect_tls(hostname, port)` returns verified protocol, cipher and
  leaf-certificate DER bytes. It sends no application request.

Sockets connect to numeric IPv4/IPv6 tuples; socket.getaddrinfo is never used
after approval. TLS uses a directly constructed PROTOCOL_TLS_CLIENT context,
TLS 1.2 or newer, CERT_REQUIRED and original-hostname verification. Direct
construction intentionally avoids SSLKEYLOGFILE environment behavior. The verified HTTP and inspect_tls APIs cannot disable trust verification.
`context.tcp.probe_tls(hostname, port, TLSProfile)` separately runs one fixed
handshake-only profile (certificate metadata, TLS 1.0, TLS 1.1 or weak TLS 1.2
suites). It returns status and metadata without sending application bytes. Public
metadata is explicitly unverified. Locally unavailable profiles are distinguished
from a handshake that did not negotiate; neither establishes universal rejection.
The weak profile is pinned to TLS 1.2 because set_ciphers does not configure
TLS 1.3 suites. No profile is accepted by HTTP.

`open()` exposes a cooperative socket capability for trusted network checks.
Such checks must close it promptly, avoid sending state-changing commands, and
checkpoint the budget during loops. The passive banner helper and TLS helper
are bounded operations; custom plugins are not an untrusted sandbox.

## Check and engine contract

`CheckContext` supplies `target`, `scan_id`, `scope`, `config`, `http`, `tcp`,
`budget` and optional engine-owned `network` survey. Register trusted local classes before invoking the engine. Each
check's `max_operations` is now an enforced per-check cap, rather than only an
estimate. It must include retries, redirects, robots and independent probes.

Return a bounded sequence of `Finding` instances for complete coverage, or
`CheckReport(findings=..., status=..., reason=...)` for explicit partial
coverage. A check that observes findings before a later failed probe should
catch the transport error and return a partial CheckReport, preserving evidence.
The engine cannot recover findings that existed only in a crashed local frame.

The engine promotes otherwise-complete checks to inconclusive if their HTTP
transport observed truncated/unsupported bodies, blocked requested redirects or
exhausted 429/503 retries. Header-only checks can avoid irrelevant body coverage
limitations. A transport failure is inconclusive; an unsupported/robots-blocked
check is skipped; unexpected plugin errors are failed. No empty production
registry is reported as a successful zero-finding scan.

Workers return findings to the engine instead of editing shared results.
Progress callbacks run in the aggregation thread; callback failures are isolated.
Output ordering is deterministic by check name and severity/rule/endpoint.
`ScanResult.to_dict()` exports counts, coverage, approved addresses/ports and
operational limits, excluding supplied UA text, local CA paths and target queries.

`ScanControl(config)` may be supplied to `engine.run(..., control=control)` for
cooperative cancellation. Its configuration and aggressive permission must
match the engine. A controller belongs to one invocation. Cancellation stops
new operations and interrupts limiter waits; existing socket I/O finishes or
hits its bounded operation timeout. KeyboardInterrupt cancels before worker
shutdown. Arbitrary Python plugin CPU loops cannot be forcibly killed by threads.

## Diagnostics and logging

Scanner logs use stable categories, check identifiers and origin-only audit
metadata. Underlying requests/urllib3 URL/header diagnostics are suppressed
only while this scanner performs HTTP work, including if the operator enables
library DEBUG logging. Unrelated clients keep their normal logging. Exceptions
are attached for programmatic diagnosis but their raw strings must not be
rendered into reports, verbose CLI output or telemetry.

No target response cache, telemetry or response persistence is created by the
engine. In-process memory remains accessible to the operator and trusted plugins.
Python does not provide guaranteed erasure of immutable body, URL or TLS bytes.

## Known private file guard

GET requests, including followed redirect hops, refuse known private-file path
patterns and obvious private file values in common file query fields. Up to three
percent-decoding rounds are inspected. HEAD remains available for metadata. This
conservative guard also refuses GET with read_body=False: it must not become a
private-file fallback. Arbitrary names cannot be universally classified; trusted
checks must keep their own deliberate URL and content boundaries.


## Network probe and result additions

`TCPTransport.probe_port(hostname, port, read_banner=True)` performs one scoped
connect and optional bounded passive read, returning a short-lived TCPProbe.
It classifies refusal/timeout/unreachable/local errors without their raw strings,
preserves successful connects when greeting deadlines expire and sends no
application bytes. NetworkSurvey consumes the raw greeting, produces a validated
PortObservation/ServiceIdentity and discards greeting references. Python does
not guarantee immutable byte erasure.

`ScanResult.to_dict()` adds nullable `attack_surface` to the existing v1 schema.
Web scans use null; network scans export counts, limits and bounded open/uncertain
identities. Other existing result keys remain compatible. CVE-cache paths are
excluded from exported limits. See NETWORK_CHECKS for matrix and display limits.
