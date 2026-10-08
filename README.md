# VulnScanner

**Authorization-first, evidence-based Python web and TCP security scanner.**

VulnScanner combines bounded anonymous web checks, a concurrent passive TCP
survey and clear offline security reports. It records minimal evidence,
confidence, remediation and coverage rather than claiming that every signal
proves an exploitable vulnerability. **v0.6.0 completes all six implementation
phases**, including the full CLI and Docker/GitHub packaging. This is a tested
development release; no independent security audit or production certification
is claimed.

## Quick start

Requires Python 3.10+; the release was executed on Linux/Python 3.12. Use a
virtual environment from the unpacked repository root:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install .
vulnscan --version
vulnscan checks
vulnscan acknowledge
```

Type **`I have permission`** exactly when prompted. Only assess systems you own
or have explicit authorization to test. An acknowledgment is a declaration,
not independent ownership verification.

```sh
# Your own local application; change the port to its actual listener.
vulnscan web http://127.0.0.1:3000 --checks headers,cookies,cors,files,disclosure \
  --output reports/local-review --format all \
  --result-json reports/local-result.json

# Your authorized private host; ports are explicit and no service commands are sent.
vulnscan net 192.168.1.10 --ports 22,80,443 --checks discovery,ports,services \
  --output reports/network-review.html

# Recreate reports offline from a saved result, without scanning again.
vulnscan-report reports/local-result.json --output reports/review-copy --format all
```

The example private address is not permission to scan someone else's network.
Exit **0** means selected coverage completed, **2** means the report preserves
skipped/inconclusive/failed coverage, **1** means refusal/error, and **130** means
interruption. Findings may be present with either 0 or 2. Existing report names
are never overwritten: use a new prefix for each assessment.

## Features

| Area | Implemented behavior |
| --- | --- |
| Headers | Applicable CSP, HSTS, framing, nosniff, Referrer/Permissions policies and advertised methods. |
| Cookies | Bounded Secure/HttpOnly/SameSite analysis; cookie names and values stay out of evidence. |
| CORS | Controlled origins and credential/cache semantics; no authenticated browser exploitation. |
| TLS | Verified certificate/hostname/date checks, HTTP-to-HTTPS observations and isolated legacy/cipher handshakes. |
| Discovery | Small authored file/dir lists, HEAD-only exposure checks, directory-listing indicators and robots/sitemap counts. |
| Input | Benign-marker reflection, new SQL-error signatures, unfollowed external redirects and explicit public-canary traversal. |
| Disclosure | Categorized comments/errors/technology hints and metadata-only source-map exposure. |
| Network | Shared, concurrent TCP-connect discovery/ports/passive fingerprints, with bounded unknown/error outcomes. |
| CVEs | Concrete advertised CPE candidates from an operator-populated private NVD cache; applicability remains unverified. |
| Reporting | Rich tables/progress, self-contained HTML, SARIF 2.1.0 JSON, GitHub Markdown and replayable native JSON. |
| Operations | Strict YAML plus CLI overrides, global pacing, attempt/deadline caps, audit UUIDs and private outputs. |
| Packaging | Installed CLI/wheel, non-root Docker Compose, isolated pinned lab, tests, GitHub CI and dependency updates. |

Checks are classes with decorator registration and typed contexts. Selection
loads only explicitly known built-ins; import does not scan. One failed check
preserves the rest of the report. See [architecture](docs/ARCHITECTURE.md),
[web checks](docs/WEB_CHECKS.md), [network checks](docs/NETWORK_CHECKS.md) and
[command reference](docs/CLI.md) for the exact detection and coverage boundaries.

## Safety defaults

- Loopback and explicit RFC1918 IPv4 are allowed by default. `.local` names must
  resolve entirely to allowed private addresses. Other names require exact
  allowlist entries. Ambiguous target syntax and URL credentials are refused.
- Public targets require **both** an exact `allowlist.txt` entry and
  `--i-have-permission`. Government/military names, metadata/special addresses
  and the AWS/Azure/Google publisher feeds remain hard-blocked.
- Provider policy ages deliberately. Public targets fail closed if it is stale;
  refresh it with the separate official-publisher update helper and review it.
- DNS/aliases are authorized once, then connections use pinned numeric peers
  with correct Host/SNI. Redirects receive a permit before any follow-up connection.
- All HTTP attempts, retries, TCP connects and TLS handshakes share the default
  **10 operations/sec** cap. Rates above 10 need `--i-know-what-im-doing` and
  still obey target scope, attempt budgets and deadlines.
- No login attempts, authentication bypass, modifying methods, executable XSS,
  data extraction or private-file content requests are implemented. Existing
  eligible query parameters are bounded; forms and recursive crawling are absent.
- Network mode uses unprivileged **TCP connect**, not raw SYN/ICMP/UDP. It sends
  no service commands. A silent peer is unknown, and an open port is inventory.
- No analytics, telemetry, target-side callbacks, external report assets,
  implicit proxies/netrc or automatic scan-side NVD traffic are used.

`--respect-robots` optionally enables conservative enforcement. Unreadable or
redirected robots rules block content access; configuration defaults to false.
A custom User-Agent must retain scanner identification and the authorization tag.
The default is `VulnScanner/1.0 (authorized-testing-only)`; a genuine repository
URL can be added after you publish your own repository.

The notice and query-free authorization events live in `~/.vulnscanner/` by
default (POSIX directory 0700/files 0600). `--state-dir` or `VULNSCAN_STATE_DIR`
can select a private operator-owned location. Python does not guarantee erasure
of immutable strings/response bytes. Minimal evidence and omission controls
reduce retained data; they are not a universal secret classifier.

## Docker and Juice Shop lab

```sh
docker compose up --build
docker compose run --rm scanner acknowledge
docker compose run --rm scanner checks
```

`up` prints help and exits; scanning is always an explicit command. The image
uses UID10001, a read-only root filesystem, dropped capabilities, bounded
resources and private named state/report volumes. The optional lab is pinned,
isolated on an internal network and published on **127.0.0.1 only**:

```sh
docker compose --profile lab up -d --wait juice-shop
docker compose run --rm scanner web http://lab.local:3000 \
  --output /reports/juice-shop-review --format all \
  --result-json /reports/juice-shop-result.json
```

Run the acknowledgment first. Default root-URL input/TLS/canary coverage may be
partial, so exit 2 can be expected. See [deployment](docs/DEPLOYMENT.md) for
volume export, private CA/policy mounts, VPS operation and cleanup, and
[Juice Shop sample status](docs/JUICE_SHOP.md) for measured versus reproducible
sample boundaries. Never use the public demo as a test dependency.

## Reports and screenshots

| Included artifact | Provenance |
| --- | --- |
| [Web HTML](docs/reports/web-assessment.html), [SARIF](docs/reports/web-assessment.json), [Markdown](docs/reports/web-assessment.md) | Actual measured synthetic loopback web fixture; original Phase 3 UUID/time preserved. |
| [Network HTML](docs/reports/network-assessment.html), [SARIF](docs/reports/network-assessment.json), [Markdown](docs/reports/network-assessment.md) | Actual measured synthetic passive greetings and a closed loopback port; original Phase 4 metadata preserved. |
| [Installed CLI HTML](docs/reports/cli-assessment.html), [SARIF](docs/reports/cli-assessment.json), [Markdown](docs/reports/cli-assessment.md) | Actual v0.6.0 wheel CLI run against an owned synthetic HTTP fixture: 3 HTTP operations, 6 findings, both selected checks complete. |

The HTML uses system fonts, responsive light/dark/print layouts, collapsed
native finding sections, mandatory autoescaping and a hash-based style CSP. It
loads no scripts, remote fonts or assets. Opening the included HTML is the
interactive report preview; these measured fixtures are not a penetration-test
claim against a real organization or Juice Shop.

![Measured synthetic web report preview](docs/images/report-preview.png)

Terminal fields use literal Rich Text. Markdown escapes prose and uses safe
variable-length evidence fences. JSON output is full SARIF 2.1.0; `--result-json`
is the separate native result schema. Imported results are unsigned and bounded;
counts are recomputed, CVSS vectors checked and unknown fields discarded.
Review engagement data before sharing it. [Reporting details](docs/REPORTING.md)
document schema limits, privacy, confidence and private new-only publication.

## Tests and GitHub

```sh
python -m pip install -r requirements-dev.txt 'setuptools>=77.0.3,<81'
python -m pip install --no-deps --no-build-isolation -e .
python -m pytest -q
ruff check scanner tests examples cli.py
ruff format --check scanner tests examples cli.py
python -m build --no-isolation
python -m pip check
```

Tests use owned loopback services and fictional advisory fixtures. The release
validation record is in [VALIDATION.md](docs/VALIDATION.md); it separates actual
local checks from unrun Docker/remote-CI/platform checks. GitHub Actions is
configured for Python 3.10/3.12 and a separate container build/smoke job; shipping
that workflow does not mean your remote run has already passed.

Repository description:

> Authorization-first Python web and TCP security scanner with bounded probes,
> passive fingerprints, offline CVE candidates, and HTML, SARIF and Markdown reports.

Use [publishing instructions](docs/GITHUB.md), [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), [ETHICS.md](ETHICS.md) and the
[verification checklist](docs/PENTEST_CHECKLIST.md). The
[full sourcebook](SOURCEBOOK.md) and [file guide](docs/FILE_GUIDE.md) include paths,
complete authored text files and two-line explanations. Licensed under MIT.
