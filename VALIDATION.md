# Version 0.6.0 validation record

Validation date: **2026-10-07 (UTC)**. Environment: Linux, CPython **3.12.14**,
dnspython **2.8.0**, requests **2.34.2**, urllib3 **2.8.0**, PyYAML **6.0.3**,
cryptography **46.0.0** (X.509 parsing and ephemeral test certificates), Rich **15.0.0**,
Jinja2 **3.1.6**, MarkupSafe **3.0.4**, jsonschema **4.26.0** (development validation),
pytest **8.4.2**, Ruff **0.13.3**.

| Check | Observed result |
| --- | --- |
| Automated suite | **369 passed**, including all 342 previous cases and 27 full-CLI cases. |
| Ruff lint and formatting | Passed. |
| Python compilation | Passed for source, examples and tests. |
| Python 3.10 grammar | All 103 Python files parsed under the 3.10 grammar. |
| Function annotation inspection | All parameters/returns annotated, excluding self/cls. |
| Editable install | Version 0.6.0 installed successfully. |
| Distribution build | Source distribution and wheel built; new configuration, tests and documentation included. |
| Installed wheel | Version 0.6.0 installed outside the checkout; bundled resources, full CLI and report replay tested. |
| Dependency consistency | pip check found no broken requirements. |
| Real HTTP | Loopback server received expected bodyless requests with original Host. |
| Numeric DNS pinning | HTTP and HTTPS still worked with socket.getaddrinfo forbidden. |
| Anonymous transport | Proxy environment variables ignored; no cookies or Authorization replayed. |
| TLS | Ephemeral CA trusted; original SNI observed; wrong hostname and untrusted CA rejected. |
| Key-log environment | SSLKEYLOGFILE did not produce a key-log file. |
| Scope on redirects | Metadata/cross-host destinations never contacted; loops/hop overflow/downgrades stopped. |
| Content bounds | Body truncation, compressed-content refusal and oversized-header rejection verified. |
| Slow response | Absolute deadline interrupted drip-fed content; a stalled TLS handshake also timed out. |
| Retries | 503 recovery and finite 429 retries counted, using deterministic virtual backoff time. |
| Robots | Policy cached; disallowed content was not fetched. |
| TCP | Actual passive loopback banner read; unapproved port rejected. |
| Engine | Concurrent workers, failed-check isolation, progress-error isolation and partial findings verified. |
| Budgets | Atomic scan/check caps, deadline during backoff and cancellation/controller-reuse cases verified. |
| Diagnostic integration | First-run notice, saved acknowledgment reuse, real GET, blocked metadata target and audit persistence verified. |
| Provider snapshot | Existing real official-feed snapshot contains **6,567** collapsed ranges. |

## Test boundaries

All target-service tests use ephemeral fixtures bound to **127.0.0.1**. Named
fixture.local/wrong.local addresses are injected at the approved resolver boundary.
They are not looked up on the Internet. CA and server keys are generated locally,
used for synthetic tests and destroyed with the temporary test directory.

The measured JSON in [DIAGNOSTIC_SAMPLE.json](DIAGNOSTIC_SAMPLE.json) comes from
running the shipped diagnostic against the local fixture. Its scan ID, time and
port are actual observations. It is a transport demonstration, not an OWASP
Juice Shop vulnerability report. First-run and subsequent-run state was isolated
in a temporary operator directory. The blocked metadata attempt contacted no
service. No Internet target was scanned.

The 86 original tests continue to cover government/military labels, public
permissions/allowlists, cloud freshness, metadata and mapped IPv6, alias inspection,
CIDR budgets, acknowledgment/audit files, symlinks, CVSS and evidence sanitization.
Phase 3 adds actual loopback positive/negative web rules and integrated orchestration.
The dedicated TLS fixtures positively negotiate TLS 1.0, TLS 1.1 and an
ECDHE-RSA-NULL-SHA TLS 1.2 suite; no legacy fixture skips occurred in this runtime.

## Publisher snapshot provenance

The snapshot shipped in Phase 1 remains unchanged. Official AWS, Microsoft Azure
Public Cloud and Google feeds were retrieved over verified HTTPS and normalized
through refresh_policy. This environment requires its approved outbound proxy;
preparation supplied a fixed-publisher fetch callback. The default updater still
disables implicit proxies and failed closed in this proxy-only environment.
Source-byte hashes identify provenance; they are not publisher signatures or
exhaustive cloud address ownership. Freshness checks remain mandatory for public
scan authorization, so operators must refresh the snapshot as it ages.

## Limits of verification

- The full scanner CLI and report-only CLI are implemented and locally tested. Docker
  files are supplied; no local Docker/Podman engine was available for build/runtime
  verification, and no standalone Compose executable was available. YAML structure
  and configuration were reviewed; a Compose runtime validation is not claimed.
- GitHub CI is configured but has not run against a published remote repository.
- Network service coverage is passive and bounded; live public target/NVD API
  execution, privileged discovery and independent assessment are unverified.
- Weak-suite coverage is limited by locally available OpenSSL suites; failed
  handshakes never establish exhaustive absence of deprecated configurations.
- No measured OWASP Juice Shop scan has been performed.
- Execution tests ran on Python 3.12; Python 3.10 grammar/dependency declarations
  were checked, but this is not Python 3.10 runtime certification.
- Windows ACL/transport execution, macOS behavior, IPv6 socket integration and
  Internet/public-address transport execution were not tested.
- In-process plugins remain trusted Python code; thread cancellation is cooperative.
- No independent security audit, certification or production-readiness claim.

The validation record describes observed checks, not proof that all defects or
all runtime/platform behaviors have been excluded.

## Phase 3 verification

- All ten checks executed together through the real concurrent engine with
  explicit findings, skipped inputs and incomplete HTTP-only TLS coverage.
- Valid CA/SNI, untrusted, expired and not-yet-valid certificates; actual legacy
  TLS 1.0/1.1 and NULL-suite handshakes; all diagnostic handshakes omit HTTP.
  Untrusted metadata collection never weakens subsequent HTTP verification.
- Missing/valid framing headers, report-only CSP, nonce-qualified inline policy,
  named-host HSTS/quoted age/duplicate first field and JSON applicability.
- Cookies omit names/values, bound parsing and handle Partitioned/duplicates;
  CORS exact credentials, reflected/null origins, invalid wildcard configuration
  and Vary wildcard cache semantics.
- Sensitive file and map HEAD-only requests, random 404 controls, SPA/soft-404
  ambiguity, no unsupported-HEAD GET fallback and scoped public-script pointers.
- XML declaration/entity/UTF-16/size restrictions, counts-only URL inventories,
  comment/stack/technology categorization with raw content omitted.
- Encoded HTML vs literal benign reflection, JSON applicability, new-vs-baseline
  SQL error signatures, duplicate query occurrences and authentication/action
  exclusions before I/O. External redirect markers are never followed.
- Explicit public traversal canary, exact controls and a universal-response
  negative case; config refuses private fixture names and invalid types.
- Shared GET guard rejects known private file paths and file parameters before
  requests, including percent-encoded names; metadata HEAD remains usable.
- `WEB_SAMPLE.json` was measured by launching the shipped example against an
  ephemeral 127.0.0.1 fixture with real default pacing: **59 HTTP attempts and
  5 TLS handshakes**, 22 synthetic findings (6 medium, 10 low, 6 informational).
  Nine checks completed and TLS was explicitly inconclusive. All CVSS values
  are null; no guessed exploit impact or Juice Shop claim is present.

The wheel includes all three bounded wordlists as shared package data. A
standard virtual-environment wheel installation was tested from outside the
source tree. Source files parse using Python 3.10 grammar; scanner/example
functions have parameter/return annotations, and public classes/methods have
docstrings. Ruff lint/format, compileall and wheel/sdist build checks passed.
These are observed tests on Linux/Python 3.12, not platform certification.


## Phase 4 verification

- All four network checks run through the engine and share one counted connect
  per pair. Real local SSH/SMTP-like greetings, closed ports, fragmentation,
  silence, byte caps and no transmitted application commands were verified.
- Numeric dialing still works with socket DNS forbidden; different ports and
  metadata addresses are refused before IO. Oversized matrices fail before
  target connections. State/audit safeguards and the web suite still pass.
- Simulated kernel refusal, timeout, unreachable and local errors stay distinct.
  Timeouts are unknown rather than closed/dead, with exact bounded uncertain
  port records in the surface. Discovery does not skip silent addresses.
- A controlled 1000-port survey verifies two-worker concurrency, rolling jobs,
  complete aggregation and 1000 reserved operations. Cancellation stops new jobs
  and preserves completed pairs; unexpected worker failures remain failed.
- Curated 100/1000 presets have exact distinct counts and explicit non-statistical
  provenance. An operator-supplied synthetic frequency fixture tests ranking,
  TCP-only parsing, insufficient rows, non-finite values and range/overlap limits.
- Passive protocol/product signatures, proper OpenSSH/ProFTPD update components,
  protocol-vs-software versions, ambiguous/adversarial greetings and complete
  MySQL-compatible framing were tested. No banner-only identity is authenticated.
- Synthetic NVD responses verify schema, rejected advisories, vector/score
  consistency, pagination, concrete CPE binding and native CVSS computation.
  These fictional test advisory IDs are not published findings or live NVD data.
- Private cache permissions (700/600), atomic replacement, absent/stale/future/
  mismatched/corrupt/symlink failures and preservation after update failure pass.
  Updater pacing uses a deterministic clock; fixed-publisher fetch refuses local
  resolutions and unsafe queries before sockets. Live API execution was not done.
- Candidate output preserves published score metadata separately from null
  target CVSS and unverified applicability. Missing cache skips before traffic;
  scans never perform automatic external lookup.
- `NETWORK_SAMPLE.json` was measured by launching the shipped runner with real
  pacing against synthetic loopback greetings and a closed port: **3 TCP connects**,
  **0 HTTP/TLS operations**, **5 informational observations**, three completed
  checks and explicitly skipped CVEs. Banners are simulated, not installed-software
  claims. UUID/timestamps/ports are actual measurements.
- Editable install, complete source/wheel builds, installed-wheel resource and
  real local network-engine smoke checks pass outside the source checkout.
  Fingerprints, curated ports and all three web wordlists are included.

Python 3.12/Linux execution, Python 3.10 grammar and function annotations were
checked. No Windows/macOS execution, IPv6 socket integration, public target scan,
live NVD API contract certification or independent audit is asserted. The actual
Phase 3 web sample is retained as an explicitly labeled earlier measured fixture.

## Phase 5 verification

- All **342 tests** pass, including 57 reporting/validation cases and all previous
  safety, transport, web and network cases. Invalid source schemas/types/times,
  duplicate coverage/JSON keys, large inputs/lists and deep JSON fail closed.
- Imported counts are recomputed. Unknown secret-bearing properties are discarded;
  scope/host/pair/omission counts and passive identity claims are checked. Null
  CVSS remains unscored, and a supplied score must match its validated vector.
- HTML adversarial closing tags, event-handler/image/script attempts and template
  expressions remain escaped literal text. The effective style hash matches the
  exact authored CSS bytes. No active elements/remote assets are generated.
- Literal Rich Text prevents markup/ANSI/OSC injection. Bidi controls are removed.
  Markdown prose escapes HTML/mention/table syntax and code fences contain embedded
  backticks. Known-secret and query-value redaction is verified across all formats.
- Existing files/symlinks remain unchanged. Mode 0600/0700 outputs/directories,
  commit-time collisions, staged cleanup and best-effort multi-file rollback pass
  on Linux. Console progress integrates with the actual engine, counting settled
  failures while preserving failed coverage. CLI stdin/export errors and coverage
  exit codes are tested without any new authorization or target requests.
- Web/network/diagnostic exports were checked using jsonschema against the official
  OASIS SARIF 2.1.0 schema fetched from its primary repository, with format checking.
  Captured schema: **112,768 bytes**, SHA-256
  `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`.
  The schema is not bundled. The shipped local validation helper was also tested
  for external-reference refusal; normal tests do not fetch the schema or network.
- The sample web report was actually opened in Chromium **153.0.8010.0** at
  desktop 1440px, mobile 390px, dark mode and print media. Authored styles were
  applied, all 22 findings were present, there was no document-width overflow,
  no page errors and only the local file request. Screenshots were visually
  inspected. Print media retains content from collapsed findings/settings.
- Sample HTML/SARIF/Markdown files preserve the original Phase 3/4 synthetic scan
  IDs, timestamps, operations, severity counts and incomplete coverage. These are
  offline exports of previous local measurements, not new scans or real advisory
  applicability assertions. No Juice Shop result is invented.
- Runtime exporters were exercised with DNS/socket connection methods forbidden;
  reference links and SARIF schema identifiers are not fetched. The report-only
  installed entry point, packaged templates, wheel/sdist and dependency consistency
  were checked outside the source checkout.

Browser verification used one Chromium/Linux environment. Firefox/Safari, assistive
technology, comprehensive accessibility conformance, mobile hardware, Windows ACLs
and cross-platform hard-link behavior remain unverified. Source reports are unsigned
and report export is not an independent security assessment or compliance audit.

## Phase 6 verification

- **27 CLI integration tests** exercise actual ephemeral HTTP/TCP services, exact
  first-run notice, saved state, state environment override, three reports plus
  native replay, private output modes and shared passive network connection counts.
- Invalid names/modes, duplicated checks, malformed limits, rate above 10 without
  its own flag and conflicting/existing/symlink output paths fail before acknowledgment
  or traffic. Parse/URL errors do not echo secret-bearing arguments or tracebacks.
- Public flags cannot override mandatory allowlists, government/metadata blocks or
  private audit persistence. Native snapshots retain the matching measured scan ID.
- Partial coverage exports remain usable and return 2. Listing/help/version perform
  no scans or authorization-state writes. YAML overrides remain settings-only.
- The scan deadline begins after notice acknowledgment; report alias normalization
  does not conceal symlink parents. Console logging stays scanner-only and literal.
- Version 0.6.0 source/wheel packaging includes policy data, templates, commands,
  Docker, CI and documentation. Installation is checked outside the source checkout.
- The README PNG was captured from the original measured Phase 3 HTML in Chromium
  153, at 1440 × 1050. One local file request, zero page errors and no horizontal
  overflow were observed. The earlier dark/mobile/print review remains applicable
  to the unchanged authored report CSS/templates.
- Base and lab image index digests were fetched from the public Docker registry
  and checked against response-byte SHA-256. GitHub action commit pins were retrieved
  from the official repositories. These preparation lookups are not scanner telemetry.
- The external application download timed out; Docker/Compose executables were
  unavailable. No measured Juice Shop scan or locally executed container build is asserted. A complete reproducible isolated
  lab workflow is in JUICE_SHOP.md. No public target was scanned.

Runtime execution remains Linux/Python 3.12. Python 3.10 syntax and declarations
are checked, with actual 3.10 runtime validation left to the configured CI job.

### Installed CLI measurement

`CLI_SAMPLE.json` was produced by the installed `vulnscan` command, outside the
source checkout, against an owned synthetic HTTP fixture. It records scan
`de5b6d91-d408-4f8f-b2b1-e73ebb54dcbe`, **3 HTTP attempts**, **6 findings**
(4 low, 2 informational) and both selected checks complete. The shipped HTML,
SARIF and Markdown were rendered from those unchanged observations; an offline
context annotation labels the fixture. Installed report replay and a separate
one-connect passive loopback SSH-like network CLI smoke also passed. This is
not an installed-software, public-network or Juice Shop assessment claim.
