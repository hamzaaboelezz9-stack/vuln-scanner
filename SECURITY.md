# Security policy

## Supported status

Version 0.6.0 ships the full scanner CLI, ten web checks, a shared passive TCP
survey, fingerprints, offline NVD candidates, safe reports and container packaging.
No independent penetration test, certification or external security
audit has been performed. Automated tests validate specific behavior and do
not establish production readiness.

## Responsible disclosure

Before publishing this repository, enable GitHub private vulnerability reporting.
Use the repository's **Security → Report a vulnerability** flow when available.
If it is unavailable, open an issue asking for a private contact channel without
including exploit details, secrets or target information. A maintainer email
address is not invented in this repository.

Include the affected version, operating system, Python version, a minimal local
reproduction, expected behavior, observed behavior and impact. Use synthetic
targets and secrets. Do not demonstrate a bypass against a third-party system.

## Trust boundaries

- CLI inputs and target responses are untrusted.
- Imported result JSON and all report fields are untrusted; report scope metadata
  does not independently establish authorization or provenance.
- Scan scope must be approved before any target service connection.
- DNS answers and aliases are untrusted until checked; approved numeric addresses
  remain pinned for the scan and are rechecked against policy at permit time.
- HTTP/socket transports use permits and numeric dialing rather than re-resolving names.
- Source code, installed dependencies, local plugins and policy files are trusted
  operator-controlled inputs. This design is not a sandbox for malicious Python.
- A legal acknowledgment or allowlist entry records intent, not ownership.
- An IP blocklist does not prove that an unblocked address is safe or privately owned.

## Design decisions

**Deny before allow:** metadata, government/military labels and covered cloud
ranges remain blocked even when explicitly allowlisted.

**Explicit private ranges:** generic `is_private` does not mean RFC1918. Default
access uses the three named private networks and loopback. Mapped IPv6 addresses
are checked as their underlying IPv4 address; translated/tunneled forms are blocked.

**No DNS re-resolution at transport time:** a permit supplies numeric addresses
and the hostname needed for Host/SNI. Resolving that hostname again would defeat
the scope gate. Local integration tests prohibit socket.getaddrinfo after approval
and verify original Host/SNI plus hostname authentication.

**Fail closed on missing evidence:** stale cloud policy, corrupt acknowledgment,
mixed prohibited DNS answers and unavailable audit storage prevent authorization.

**Honest findings:** severity and confidence are independent. Inconclusive or
failed checks cannot become clean passes. CVSS scores have reproducible vectors.

**Minimal persistence:** audit records store target origins rather than query
values or paths. Findings bound observations and redact common secret-bearing
fields. Redaction is not a universal detector; implemented checks avoid persisting
private file contents and entire response bodies. Public-page/script bytes are
inspected transiently; Python cannot guarantee memory erasure.

**Bounded concurrency:** one monotonic limiter spaces operations across workers.
Higher rates need explicit aggressive permission. HTTP applies bounded 429/503
retries and shared backoff. Atomic child/scan attempt budgets and deadlines limit
work. HTTP watchdogs bound slow headers and bodies in addition to per-read timeouts.

**Anonymous requests:** only bodyless GET, HEAD and OPTIONS are accepted. There
are no implicit proxies, netrc credentials or replayed cookies. Every HTTP exchange
uses an isolated pool and revalidates its permit. Host remains the approved name.

**Verified HTTP TLS:** TLS 1.2+, trusted CA validation and hostname verification remain
enabled for all HTTPS requests. Private labs can supply a CA bundle. SSLKEYLOGFILE is not honored.
Cross-host and HTTPS-to-HTTP redirects are not followed automatically.

**Isolated diagnostic TLS:** fixed TLS 1.0/1.1/weak-suite and public certificate
profiles use unauthenticated handshakes without application data. These contexts
are never supplied to the HTTP adapter. Diagnostic certificates are labeled
unverified; successful legacy negotiation is positive evidence, while failures
never prove that every cipher/protocol is disabled. Local OpenSSL limitations
remain explicit coverage gaps.

**Non-exploit probes:** modifying verbs are only inventoried through OPTIONS.
XSS uses inert characters without executable syntax; SQL checks append one quote
only on existing non-auth fields. Traversal needs an owner-created public canary.
Sensitive files/maps use HEAD with randomized not-found controls and no GET
fallback. A conservative shared GET guard refuses known private file patterns
including decoded paths and common file parameter values. It is defense in depth,
not a universal classifier of private data or a sandbox.

**Bounded content:** headers are capped before parsing; bodies are capped while
streaming. Unexpectedly compressed bodies are not decompressed. Content limits
and blocked followed redirects remain visible as incomplete coverage. Library
HTTP diagnostics are suppressed in the scanner's active context to avoid leaking
raw URLs or headers under DEBUG logging.

## Known limitations

- Provider coverage is limited to the configured public feeds; Azure sovereign
  clouds and arbitrary customer-owned networks are not exhaustively covered.
- Blocking `gov` and `mil` DNS labels does not identify every government-owned
  site under other suffixes or a bare government IP address.
- The resolver supports configured unicast DNS, not mDNS or hosts-file entries.
- POSIX file ownership, modes and no-follow behavior are tested on Linux.
  Windows ACL enforcement and macOS-specific behavior have not been verified.
- Audit files can be edited by the local account; they are not signed or tamper-proof.
- Proxy-only environments cannot use the default direct-network policy updater.
- Transport integration tests ran against ephemeral loopback HTTP/TLS servers.
  Web checks include actual legacy/NULL-suite handshakes; network checks include
  local sockets, bounded thousand-port simulation and synthetic catalog responses.
  Real Internet target scans, live NVD API integration and independent review remain
  outstanding.
- HTTP and standalone named socket attempts use the first approved address with
  no implicit fallback. The network survey explicitly enumerates every approved
  numeric address under the matrix budget.
- Trusted plugins receive in-process socket capabilities. They must cooperate
  with cancellation and close sockets; arbitrary Python CPU loops cannot be
  forcibly terminated by ThreadPoolExecutor.
- Existing requests in flight may finish after a backoff/cancellation signal,
  bounded by their operation timeout. This is not a network isolation sandbox.
- Python does not guarantee erasure of immutable URL, response or certificate
  bytes. Do not publish private response bodies or enable raw exception tracing
  against real targets; checks must produce minimal sanitized evidence.


## Network and catalog boundaries

Built-in network checks share one approved matrix and send no application bytes.
They retain TCP-connect outcomes and constrained passive identities, not raw
welcome lines. Open listeners are inventory; silence is unknown. Thread concurrency
is bounded by rolling jobs and all attempts use the same rate/operation/deadline
controller. Completed observations survive cancellation; unknown/error coverage
is explicit. Privileged ICMP/raw SYN, UDP, active commands and authentication are
not provided by this implementation.

CVE scans read only an operator-configured local cache. The separate updater
fetches one bounded filtered page from the fixed public NVD API, never a supplied
URL, using numeric dialing plus verified original-hostname TLS. No target host,
address, full banner or credential is sent. Its publisher resolution refuses
local/metadata addresses; source/CA files remain trusted operator inputs. Cache
entries bind a concrete CPE and freshness and contain only public advisory metadata.
The cache is not signed: the local account can change it. Candidate identity,
backports, module prerequisites and installed applicability remain unverified.
Published CVSS metrics are not presented as a confirmed target assessment.

Finding/surface display caps are reported alongside full aggregate counts.
Curated port coverage is not falsely labeled a statistical ranking; an explicit
operator-supplied frequency file enables ranked selection. Arbitrary local plugins
still receive trusted in-process socket capabilities and are not sandboxed.

## Report handling

Source result JSON is unsigned, untrusted metadata. Report exporters recompute
counts, validate scope/surface consistency and CVSS vectors, retain explicit
coverage, discard unknown properties and never promote passive advertisements to
confirmed installed-software identity. Imported scope does not prove permission.
Known-secret redaction is a secondary safeguard, not a universal classifier.
Review reports before publishing or pasting them into issue trackers.

HTML uses fixed packaged templates, mandatory autoescaping and a hash-based style
CSP. No scripts, event handlers, external assets, font downloads or telemetry are
present. Terminal fields use literal Rich Text; control/bidi characters are removed.
Markdown prose is escaped and evidence uses a fence longer than any embedded
backtick run. References are HTTPS without userinfo/query/fragment.

Reports are staged privately and atomically published to new paths; existing
files/symlinks are not overwritten. Use operator-controlled directories. Parent
symlink preflight is not a sandbox against malicious concurrent directory changes.
Multiple-file export uses best-effort rollback; interruption/cleanup failure can
leave private partial/staged output. POSIX permissions are tested; Windows ACLs
and filesystems without hard links are not certified. Reports are not signed or
tamper evident. If serving HTML, separately enforce access controls and an HTTP
frame-ancestors policy; that directive cannot be enforced by a meta CSP.

See docs/REPORTING.md for exact input/output bounds, local schema validation,
format semantics and verification limits. Reporting performs no target/DNS/CVE
requests and does not send findings to other services.

## CLI and container decisions

The full CLI loads only explicitly known built-ins and preflights mode, selection,
operational limits and export names before target traffic. It catches expected
errors as authored categories, omitting raw URL/OS/DNS/TLS diagnostics. Verbose
mode adds minimal finding evidence without enabling root/urllib3 debug logging.
Invalid syntax is not a scan; scope decisions that reach the gate are audited.

Container state is explicitly placed in an owner-only named volume. The scanner
uses UID10001, read-only root, dropped capabilities and no-new-privileges. It
needs no public listener or privileged raw sockets. Docker does not protect data
from a compromised host root account or make trusted plugins safe to execute.
The intentionally vulnerable Juice Shop profile is opt-in, pinned, loopback-bound
and attached to an internal network. No public demo is contacted.

GitHub workflow actions and image bases are pinned; routine dependency changes
require review. Runtime direct dependencies are version-pinned, while transitive
build resolution remains an upstream supply-chain boundary. A configured CI job
is not evidence that CI or the Docker image has already executed successfully.
See docs/VALIDATION.md for the release's actual verification record.
