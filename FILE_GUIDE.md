# Delivered file guide

VulnScanner v0.6.0: full authorized web/network CLI, safe offline reports, container/GitHub packaging and measured local verification.

Paths identify the original generated workspace; the archive preserves the repository-relative layout.

## .dockerignore

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/.dockerignore`

Limits the container build context to runtime source, trusted data and required metadata.  
Omits development caches, reports, state, test tooling and unrelated private files.

## .env.example

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/.env.example`

Documents the optional loopback Juice Shop host port and local state override.  
Contains no secrets or automatic permission grants and keeps vulnerable lab binding private.

## .github/dependabot.yml

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/.github/dependabot.yml`

Requests reviewed weekly Python, GitHub Actions and Docker dependency updates.  
Does not automatically approve releases or assert vulnerability-free dependencies.

## .github/workflows/ci.yml

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/.github/workflows/ci.yml`

Defines full-commit-pinned Python lint/test/build/wheel and separate Docker smoke jobs.  
Uses read-only repository permission and tests installed resources outside the checkout.

## .gitignore

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/.gitignore`

Excludes local environments, caches, distributions, private reports and environment files.  
Retains only the non-secret environment example for publication.

## CHANGELOG.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/CHANGELOG.md`

Records delivered behavior across all six implementation phases through v0.6.0.  
Keeps implemented features separate from certification or remote-runtime claims.

## CONTRIBUTING.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/CONTRIBUTING.md`

Documents development commands, meaningful tests and bounded evidence/transport requirements.  
Explains trusted built-ins, dependency review and private vulnerability reporting.

## Dockerfile

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/Dockerfile`

Builds runtime wheels from a digest-pinned Python base and installs the packaged CLI.  
Runs UID10001 with private state/report directories and help as the safe default command.

## ETHICS.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/ETHICS.md`

Describes authorized assessment practice and careful evidence handling.  
Makes clear that private addressing and legal acknowledgment do not establish ownership.

## GITHUB_DESCRIPTION.txt

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/GITHUB_DESCRIPTION.txt`

Provides the complete ready-to-paste repository description.  
Accurately names bounded scanning, passive identities and offline report/CVE behavior.

## LICENSE

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/LICENSE`

Grants MIT permissions for the authored project code.  
Preserves the copyright and warranty terms for redistribution.

## MANIFEST.in

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/MANIFEST.in`

Includes source, tests, reports, preview image, container files and CI in source distributions.  
Excludes releases, build residue and generated Python bytecode.

## NOTICE.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/NOTICE.md`

Attributes focused dependencies, public provider metadata and primary design references.  
Identifies independently authored templates and separate official-schema verification.

## README.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/README.md`

Explains installation, full CLI, scope rules, Docker workflows and GitHub publication.  
Links measured samples, a real report preview, tests, documentation and explicit validation limits.

## SECURITY.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/SECURITY.md`

Defines disclosure and the scope, transport, catalog, report, CLI and container trust boundaries.  
Records unsigned metadata, trusted plugins, private outputs and platform/runtime limits.

## SOURCEBOOK.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/SOURCEBOOK.md`

Reproduces every authored text file, full code and policy data with paths and explanations.  
Includes the folder listing and binary preview metadata without recursively reproducing itself.

## allowlist.txt

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/allowlist.txt`

Starts with no authorized public targets and documents the accepted entry syntax.  
Requires operators to add only exact targets covered by their assessment permission.

## cli.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/cli.py`

Provides the complete source-checkout entry point for the full scanner.  
Delegates to the same installed CLI implementation and stable coverage exit codes.

## config.yaml

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/config.yaml`

Defines validated scan limits, verified TLS, public canary, banner window and local cache.  
Permission flags stay separate from YAML and catalog fetching is never automatic.

## data/fingerprints/services.json

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/data/fingerprints/services.json`

Contains bounded authored passive greeting patterns and limited concrete product mappings.  
Provides no executable service payloads, guesses from ports or claimed authenticated versions.

## data/policy/cloud-ranges.json

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/data/policy/cloud-ranges.json`

Contains real normalized AWS, Azure Public Cloud and Google-owned range data.  
Records capture time, source hashes and conservative publication freshness anchors.

## data/ports/common.json

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/data/ports/common.json`

Contains exactly 100 and 1000 independently curated TCP coverage ports.  
Discloses the non-statistical selection basis and IANA reference.

## data/wordlists/common_dirs.txt

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/data/wordlists/common_dirs.txt`

Lists the administrative and public listing paths used for bounded discovery.  
Avoids a large brute-force corpus or recursive crawling.

## data/wordlists/sensitive_files.txt

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/data/wordlists/sensitive_files.txt`

Lists twelve curated config, repository, database and backup metadata candidates.  
Used only with HEAD and randomized controls, never private-file GET requests.

## data/wordlists/xss_payloads.txt

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/data/wordlists/xss_payloads.txt`

Contains the single inert marker template with quotes, angles and ampersand.  
Includes no script, event handler, external callback or code execution syntax.

## docker-compose.yml

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docker-compose.yml`

Applies read-only root, dropped capabilities, resource caps and retained private volumes.  
Provides an opt-in pinned Juice Shop lab on an internal network with a loopback host port.

## docs/ARCHITECTURE.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/ARCHITECTURE.md`

Explains authorization, bounded transports, shared surveys, CLI and offline report responsibilities.  
Shows explicit fixed-publisher updates and private publication rather than scan-side telemetry.

## docs/CLI.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/CLI.md`

Documents every command/flag, default, configuration precedence and stable exit meaning.  
Explains public/rate permission, private report publication and input/network coverage limits.

## docs/CLI_SAMPLE.json

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/CLI_SAMPLE.json`

Contains actual installed v0.6.0 CLI output from an owned synthetic HTTP fixture.  
Retains measured UUID/time, three HTTP operations and six findings with an offline context label.

## docs/DEPLOYMENT.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/DEPLOYMENT.md`

Provides Docker, isolated lab, private-volume export and authorized VPS operation commands.  
Explains pinned images, container limits, policy freshness and actual verification status.

## docs/DIAGNOSTIC_SAMPLE.json

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/DIAGNOSTIC_SAMPLE.json`

Contains actual JSON output from a measured loopback transport diagnostic.  
Records real scan metadata while making no vulnerability or Juice Shop claim.

## docs/FILE_GUIDE.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/FILE_GUIDE.md`

Explains every delivered file in two lines with its original full absolute workspace path.  
Maps normal repository files to implementation, tests, samples and documentation.

## docs/FOLDER_STRUCTURE.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/FOLDER_STRUCTURE.md`

Lists the complete delivered repository structure grouped by directory.  
Excludes local caches, build residue, releases and private operator output.

## docs/GITHUB.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/GITHUB.md`

Provides description, topic suggestions, publication commands and release guidance.  
Uses real operator ownership and private reporting rather than fictional accounts or audit badges.

## docs/JUICE_SHOP.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/JUICE_SHOP.md`

Provides a complete reproducible workflow to generate an actual isolated local lab report.  
Records blocked release-environment execution and includes no fabricated Juice Shop findings.

## docs/NETWORK_CHECKS.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/NETWORK_CHECKS.md`

Maps network modules to behavior, scope, coverage, limits and cache workflow.  
Explains TCP outcomes simply and distinguishes curated coverage from real frequency ranking.

## docs/NETWORK_SAMPLE.json

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/NETWORK_SAMPLE.json`

Contains actual runner output for synthetic SSH/SMTP loopback greetings and a closed port.  
Retains measured metadata while explicitly avoiding installed-software, live-NVD or Juice Shop claims.

## docs/PENTEST_CHECKLIST.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/PENTEST_CHECKLIST.md`

Lists actionable scope, traffic, uncertainty, output-security and packaging verification steps.  
Separates owned-fixture tests from independent assessment or compliance certification.

## docs/REPORTING.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/REPORTING.md`

Documents report APIs, commands, formats, bounds and output-security decisions.  
Explains full CLI publication, native replay, real sample provenance and coverage semantics.

## docs/TRANSPORTS.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/TRANSPORTS.md`

Specifies transport, engine, budgets, network probes and additive surface output.  
Documents short-lived greeting bytes and trusted in-process plugin capabilities.

## docs/VALIDATION.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/VALIDATION.md`

Records 369 tests, installed CLI measurements, builds, SARIF and actual preview verification.  
Separates observed Linux checks from unrun Docker/Juice Shop/remote-CI/platform claims.

## docs/WEB_CHECKS.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/WEB_CHECKS.md`

Maps every web check to probes, evidence, interpretation and explicit limits.  
Explains safe public-canary setup and reproducing the measured local fixture.

## docs/WEB_SAMPLE.json

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/WEB_SAMPLE.json`

Contains actual UUID, timing, port, findings and coverage from the shipped web runner.  
Explicitly identifies the synthetic loopback fixture and incomplete TLS coverage.

## docs/images/report-preview.png

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/images/report-preview.png`

Shows the original measured Phase 3 synthetic web report in Chromium at 1440 by 1050.  
Is a real local screenshot with no fetched remote assets, not a generated or Juice Shop image.

## docs/reports/cli-assessment.html

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/reports/cli-assessment.html`

Contains self-contained HTML rendered from the measured installed CLI result.  
Preserves original evidence, complete selected coverage and explicit synthetic provenance.

## docs/reports/cli-assessment.json

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/reports/cli-assessment.json`

Contains SARIF 2.1.0 rendered from the measured installed CLI result.  
Preserves original evidence, complete selected coverage and explicit synthetic provenance.

## docs/reports/cli-assessment.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/reports/cli-assessment.md`

Contains GitHub Markdown rendered from the measured installed CLI result.  
Preserves original evidence, complete selected coverage and explicit synthetic provenance.

## docs/reports/network-assessment.html

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/reports/network-assessment.html`

Contains self-contained HTML exported from the previous measured synthetic network result.  
Preserves original scan metadata, uncertainty and provenance without fabricating a new assessment.

## docs/reports/network-assessment.json

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/reports/network-assessment.json`

Contains SARIF 2.1.0 exported from the previous measured synthetic network result.  
Preserves original scan metadata, uncertainty and provenance without fabricating a new assessment.

## docs/reports/network-assessment.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/reports/network-assessment.md`

Contains GitHub-friendly Markdown exported from the previous measured synthetic network result.  
Preserves original scan metadata, uncertainty and provenance without fabricating a new assessment.

## docs/reports/web-assessment.html

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/reports/web-assessment.html`

Contains self-contained HTML exported from the previous measured synthetic web result.  
Preserves original scan metadata, uncertainty and provenance without fabricating a new assessment.

## docs/reports/web-assessment.json

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/reports/web-assessment.json`

Contains SARIF 2.1.0 exported from the previous measured synthetic web result.  
Preserves original scan metadata, uncertainty and provenance without fabricating a new assessment.

## docs/reports/web-assessment.md

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/docs/reports/web-assessment.md`

Contains GitHub-friendly Markdown exported from the previous measured synthetic web result.  
Preserves original scan metadata, uncertainty and provenance without fabricating a new assessment.

## examples/authorize_scope.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/examples/authorize_scope.py`

Runs an interactive authorization preflight and prints approved scope metadata.  
Makes no target-service connections and is suitable for reviewing the first-run workflow.

## examples/network_checks.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/examples/network_checks.py`

Runs approved network checks with exact/range/preset ports and validated CLI overrides.  
Emits sanitized JSON and incomplete coverage; separate flags grant public/aggressive permission.

## examples/report_result.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/examples/report_result.py`

Runs the complete report-only entry point directly from a source checkout.  
Supports console output and HTML/SARIF/Markdown export with documented flags.

## examples/transport_diagnostic.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/examples/transport_diagnostic.py`

Runs a real anonymous HTTP diagnostic through the approved scope and engine.  
Requires first-run permission and emits no vulnerability findings or response body.

## examples/validate_sarif.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/examples/validate_sarif.py`

Validates exported SARIF against an operator-supplied local official schema.  
Rejects remote schema references and reports categories without echoing raw findings.

## examples/web_checks.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/examples/web_checks.py`

Runs all ten anonymous web checks or a selected subset after scope approval.  
Keeps stdout valid JSON, requires first-run notice and reports incomplete coverage through exit status.

## pyproject.toml

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/pyproject.toml`

Defines v0.6.0, runtime/development dependencies, package data and both installed commands.  
Installs the provider policy, network/web resources and authored reporting templates.

## requirements-dev.txt

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/requirements-dev.txt`

Includes runtime dependencies and pinned pytest, Ruff, build and jsonschema.  
Supports reproducible local tests, builds and optional offline schema verification.

## requirements.txt

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/requirements.txt`

Pins the focused DNS/HTTP/config/TLS/terminal/template runtime dependencies.  
Keeps development-only schema validation outside runtime installation.

## scanner/__init__.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/__init__.py`

Defines the package identity and current development version.  
Importing it has no scanning or network side effects.

## scanner/checks/__init__.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/__init__.py`

Marks the explicitly loaded web/network check package.  
Importing the package performs no scan or arbitrary plugin discovery.

## scanner/checks/base.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/base.py`

Defines check metadata, reports, registry and typed transport/survey capabilities.  
Validates check selection and keeps partial coverage separate from security findings.

## scanner/checks/network/__init__.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/network/__init__.py`

Explicitly loads four fixed decorated network check classes.  
Importing the package performs no scans, DNS or catalog requests.

## scanner/checks/network/common.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/network/common.py`

Constructs minimal network evidence and coverage while bounding findings.  
Preserves completed observations and distinguishes worker failure from host silence.

## scanner/checks/network/cves.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/network/cves.py`

Reads fresh local catalog entries for supported concrete advertised CPEs.  
Keeps published advisory scores separate from unverified target applicability and CVSS.

## scanner/checks/network/discovery.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/network/discovery.py`

Inventories TCP responses without requiring privileged discovery packets.  
Does not equate silence with a dead host or skip unresponsive approved addresses.

## scanner/checks/network/ports.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/network/ports.py`

Reports successful TCP listeners as informational attack surface.  
Keeps refusal, timeout, unreachable and local errors distinct without arbitrary error text.

## scanner/checks/network/services.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/network/services.py`

Reports constrained identities from passive greetings on the same counted connection.  
Labels advertisements unverified and leaves silent/unrecognized services unknown.

## scanner/checks/network/survey.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/network/survey.py`

Collects one bounded host/port matrix using a rolling worker set and shared results.  
Keeps only constrained identities, explicit incomplete states and bounded surface records.

## scanner/checks/web/__init__.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/web/__init__.py`

Loads a fixed list of ten decorated built-in web classes.  
Imports register metadata without resolving targets or scanning.

## scanner/checks/web/common.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/web/common.py`

Provides partial-finding preservation, minimal evidence and bounded HTML/query helpers.  
Excludes authentication/action fields and validates referenced origins without DNS.

## scanner/checks/web/cookies.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/web/cookies.py`

Parses bounded independent Set-Cookie lines for flag and prefix signals.  
Reports only line numbers and attribute categories, with malformed coverage visible.

## scanner/checks/web/cors.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/web/cors.py`

Uses two inert origins, null and GET preflight to observe CORS policy.  
Distinguishes credentialed reflection from browser-blocked wildcard configurations.

## scanner/checks/web/disclosure.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/web/disclosure.py`

Categorizes technology/comment/error signals and source-map success metadata.  
Public scripts stay in memory and source maps are HEAD-only; raw values are omitted.

## scanner/checks/web/files.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/web/files.py`

Uses HEAD-only sensitive-file candidates plus bounded public directory/metadata inspection.  
Random not-found controls prevent generic success pages from becoming confirmed exposure claims.

## scanner/checks/web/headers.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/web/headers.py`

Checks security-header configuration and OPTIONS method advertisement.  
Recognizes CSP framing alternatives and never sends PUT, DELETE or TRACE.

## scanner/checks/web/redirect.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/web/redirect.py`

Checks whether an existing redirect field controls a 3xx Location hostname.  
Uses reserved fresh marker destinations without following or resolving them.

## scanner/checks/web/sqli.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/web/sqli.py`

Compares baseline and single-quote responses for new DB-error families.  
Avoids logic, timing, authentication bypass and data-extraction payloads.

## scanner/checks/web/tls.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/web/tls.py`

Analyzes verified trust, certificate dates, HTTP upgrades and actual legacy/weak negotiation.  
Labels public unverified metadata and local OpenSSL gaps without insecure HTTP fallback.

## scanner/checks/web/traversal.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/web/traversal.py`

Compares an operator-created public canary with missing and basename controls.  
Uses only a single parent prefix and never generates private or OS file probes.

## scanner/checks/web/xss.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/checks/web/xss.py`

Tests existing eligible query fields with one inert HTML metacharacter marker.  
Reports literal reflection as potential unsafe output without executing scripts.

## scanner/cli.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/cli.py`

Implements web/net, check listing, exact acknowledgment and strict configuration overrides.  
Preflights permissions/exports, invokes the shared engine and privately publishes replayable reports.

## scanner/core/__init__.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/core/__init__.py`

Marks the validated data-model package.  
Does not construct targets, resolve DNS or perform scans on import.

## scanner/core/config.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/core/config.py`

Loads bounded safe YAML with duplicate, alias and strict type validation.  
Applies explicit overrides and exports limits without private paths or supplied text.

## scanner/core/cvss.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/core/cvss.py`

Validates complete CVSS v3.1 base vectors and computes their scores.  
Uses FIRST equations and integer roundup to make scoring reproducible.

## scanner/core/engine.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/core/engine.py`

Runs trusted check workers under authorization and shared operation/rate/deadline controls.  
Creates one network survey, rejects oversized matrices and aggregates surface/coverage deterministically.

## scanner/core/errors.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/core/errors.py`

Defines stable transport/coverage errors and a numeric certificate verification diagnosis.  
Suppresses raw remote exception strings when constructing findings or coverage.

## scanner/core/finding.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/core/finding.py`

Defines findings, severity, confidence and bounded request/response observations.  
Sanitizes persisted evidence and allows CVSS to remain absent when impact is unknown.

## scanner/core/network.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/core/network.py`

Defines bounded TCP outcomes and minimal advertised-service observations.  
Separates protocol revisions from software versions and hides raw greetings from repr.

## scanner/core/result.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/core/result.py`

Aggregates findings, counts, timing, authorized scope and explicit check outcomes.  
Adds nullable attack-surface summaries without changing existing result-field meanings.

## scanner/core/session.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/core/session.py`

Prepares scoped bodyless HTTP with bounded content, redirects, retries and robots rules.  
Refuses known private-file GET routes before each hop and preserves duplicate headers.

## scanner/core/target.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/core/target.py`

Validates and normalizes URL, IP, hostname and CIDR inputs.  
Rejects ambiguous numeric addresses and provides query-free audit identifiers.

## scanner/core/transport.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/core/transport.py`

Dials approved numeric peers for HTTP/TLS, passive banners and classified port probes.  
Preserves successful handshakes through read limits and sends no network probe commands.

## scanner/reporting/__init__.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/reporting/__init__.py`

Marks the offline reporting package without network or import side effects.  
All renderers consume a validated snapshot rather than target access capabilities.

## scanner/reporting/cli.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/reporting/cli.py`

Implements the installed offline vulnscan-report command and coverage exit status.  
Reads existing results only and outputs authored error categories without scan traffic.

## scanner/reporting/console.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/reporting/console.py`

Presents literal-text Rich findings, coverage tables and adaptive terminal layouts.  
Provides an engine-compatible progress callback that counts settled failures accurately.

## scanner/reporting/export.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/reporting/export.py`

Prepares one or three formats from a single immutable report snapshot.  
Separates rendering from private publication so the CLI can include a native result snapshot.

## scanner/reporting/html.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/reporting/html.py`

Renders fixed autoescaped Jinja templates and hashes exact authored CSS for CSP.  
Never trusts source HTML or loads external assets, scripts or reference URLs.

## scanner/reporting/io.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/reporting/io.py`

Loads bounded regular JSON and privately stages up to four new output files.  
Refuses duplicate/deep input, symlink paths and overwrites with best-effort publication rollback.

## scanner/reporting/json_export.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/reporting/json_export.py`

Exports SARIF 2.1.0 fields, stable fingerprints and recognized evidence extensions.  
Retains null CVSS and confidence without inventing code lines or fetching schema URLs.

## scanner/reporting/markdown.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/reporting/markdown.py`

Creates GitHub-friendly report text with escaped prose and dynamically bounded fences.  
Contains untrusted evidence safely and preserves references, remediation and coverage.

## scanner/reporting/model.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/reporting/model.py`

Validates bounded source results and creates an immutable shared report snapshot.  
Recomputes counts and retains coverage while discarding unknown or inconsistent metadata.

## scanner/reporting/templates/report.css

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/reporting/templates/report.css`

Provides authored responsive light/dark/print layouts using system fonts only.  
Ensures collapsed report content is visible for printing without JavaScript.

## scanner/reporting/templates/report.html

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/reporting/templates/report.html`

Defines the complete executive summary, scope, inventory, findings and action report.  
Uses escaped source values, native collapsible sections and explicit uncertainty labels.

## scanner/safety/__init__.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/safety/__init__.py`

Marks the authorization and policy package.  
Imports alone do not acknowledge permission or initiate target connections.

## scanner/safety/authorization.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/safety/authorization.py`

Validates saved permission, scope, DNS aliases, addresses, ports and origins.  
Returns an immutable pinned scope only after its audit record is persisted.

## scanner/safety/budget.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/safety/budget.py`

Coordinates scan deadlines, cancellation and atomic child/global operation caps.  
Shares one rate limiter and prevents controller reuse across scan identifiers.

## scanner/safety/cloud_updates.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/safety/cloud_updates.py`

Refreshes official AWS/Azure/Google feeds through verified fixed-publisher preparation.  
Separates policy update IO from scans and preserves prior snapshots on failure.

## scanner/safety/io_deadline.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/safety/io_deadline.py`

Closes the currently owned socket at an absolute HTTP/TLS operation deadline.  
Transfers watchdog ownership when TLS wraps TCP and always cancels cleanup timers.

## scanner/safety/policy.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/safety/policy.py`

Parses exact allowlists and validates fresh provider-range policies.  
Makes hard blocks override permissions and normalizes IPv4-mapped IPv6 addresses.

## scanner/safety/probes.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/safety/probes.py`

Recognizes obvious encoded config, repository, backup, source-map and OS file targets.  
Refuses GET below the checks while preserving HEAD-only metadata inspection.

## scanner/safety/rate_limit.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/safety/rate_limit.py`

Spaces operations across concurrent workers using one monotonic clock.  
Requires aggressive-mode permission above the default rate and provides bounded backoff.

## scanner/safety/resolver.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/safety/resolver.py`

Performs bounded A/AAAA queries and records CNAME/DNAME names.  
Returns numeric addresses suitable for pinning and rejects oversized or incomplete answers.

## scanner/safety/state.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/safety/state.py`

Stores the exact notice acknowledgment and appends bounded JSON audit events.  
Enforces POSIX owner-only files and rejects symlinks and invalid file ownership or types.

## scanner/utils/__init__.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/utils/__init__.py`

Marks shared utilities used by models and later scanning components.  
Introduces no logging handlers, persistence or network requests on import.

## scanner/utils/cve.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/utils/cve.py`

Validates compact owner-only NVD cache data and provides a separate publisher updater.  
Uses verified fixed-host HTTPS with limits; no automatic scan lookup or custom version matching.

## scanner/utils/evidence.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/utils/evidence.py`

Redacts URL query values and common secret-bearing fields from bounded text.  
Neutralizes terminal controls while documenting that regex is not a universal secret detector.

## scanner/utils/fingerprints.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/utils/fingerprints.py`

Recognizes bounded passive protocol/product/version signatures and supported CPE updates.  
Never infers a product from port number or preserves arbitrary greeting strings.

## scanner/utils/http.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/utils/http.py`

Supplies the pinned urllib3 HTTP adapter, header cap and scoped log suppression.  
Uses the shared absolute watchdog and retains hostname authentication.

## scanner/utils/logger.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/utils/logger.py`

Configures scanner-only Rich logging using literal text and authored diagnostics.  
Avoids root HTTP debug logs, raw exceptions, tracebacks and linked paths.

## scanner/utils/ports.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/utils/ports.py`

Parses exact bounded selections and independently curated 100/1000 presets.  
Supports explicit operator-owned frequency databases without shipping third-party rank data.

## scanner/utils/resources.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/utils/resources.py`

Resolves six enumerated trusted policy/network/web resources in source or installed wheels.  
Bounds trusted reads and refuses arbitrary resource paths.

## scanner/utils/wordlists.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/scanner/utils/wordlists.py`

Loads only three trusted bounded packaged lists with strict path validation.  
Supports source checkouts and standard installed-wheel shared data.

## tests/__init__.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/__init__.py`

Marks the isolated test support package.  
Importing it does not start servers or modify operator state.

## tests/conftest.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/conftest.py`

Creates isolated acknowledged state and synthetic provider policies.  
Transport test support uses only ephemeral loopback services.

## tests/generate_network_sample.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/generate_network_sample.py`

Launches the shipped runner against synthetic local greeting fixtures with real pacing.  
Writes measured UUID/time/port/counts while explicitly labeling simulated identities.

## tests/generate_web_sample.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/generate_web_sample.py`

Creates synthetic loopback routes and launches the shipped runner with actual pacing.  
Writes measured findings/metadata without inventing a Juice Shop assessment.

## tests/lab.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/lab.py`

Serves ephemeral loopback HTTP/TLS fixtures with synthetic routes and local CA keys.  
Tests real sockets without contacting public targets or retaining real credentials.

## tests/network_lab.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/network_lab.py`

Serves ephemeral synthetic greeting listeners exclusively on IPv4 loopback.  
Records counts and unexpected client bytes to verify one-connect/passive behavior.

## tests/report_support.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/report_support.py`

Constructs deterministic fictional report-only findings for output-security tests.  
Clearly distinguishes these fixtures from measured target vulnerabilities.

## tests/test_budget.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_budget.py`

Races atomic reservations and checks child limits, cancellation and backoff deadlines.  
Verifies concurrent callers cannot exceed a shared operation cap.

## tests/test_cli.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_cli.py`

Exercises 27 meaningful full-CLI integration and pre-traffic refusal cases.  
Uses owned HTTP/TCP fixtures, exact notices and private exports without external scans.

## tests/test_config.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_config.py`

Rejects malformed YAML, unsafe constructors, aliases, deep nesting and invalid limits.  
Verifies direct construction and override behavior match the safe loader contract.

## tests/test_cookies.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_cookies.py`

Bounded flag parsing, malformed/duplicate attributes and secret omission.  
Uses isolated synthetic inputs or ephemeral loopback services without scanning public targets.

## tests/test_cors.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_cors.py`

Origin reflection, null/wildcard semantics and Vary cache behavior.  
Uses isolated synthetic inputs or ephemeral loopback services without scanning public targets.

## tests/test_cve.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_cve.py`

Exercises fictional catalog response validation, private cache and candidate handling.  
Tests freshness, symlinks, pacing and private publisher refusal without real advisory assertions.

## tests/test_engine.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_engine.py`

Tests concurrent orchestration using explicitly synthetic diagnostic plugins.  
Verifies failure isolation, coverage promotion, limits and preserved partial observations.

## tests/test_headers.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_headers.py`

Real header/CSP/HSTS and method-advertisement positive/negative fixtures.  
Uses isolated synthetic inputs or ephemeral loopback services without scanning public targets.

## tests/test_models.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_models.py`

Verifies known CVSS vectors, evidence redaction and explicit incomplete coverage.  
Tests the concrete check registry without making network requests.

## tests/test_network.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_network.py`

Checks real sockets, shared surveys, numeric scope, uncertainty, caps and concurrency.  
Includes thousand-port simulation, cancellation and unexpected-worker failure cases.

## tests/test_network_data.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_network_data.py`

Tests strict port/range/preset parsing and constrained passive fingerprints.  
Verifies provenance, update mapping and malformed/ambiguous greetings without public scans.

## tests/test_policy.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_policy.py`

Validates source metadata, freshness, malformed snapshots and atomic refresh behavior.  
Uses synthetic publisher feeds and verifies conservative timezone handling.

## tests/test_rate_limit.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_rate_limit.py`

Checks invalid rates, aggressive permission, retry budgets and concurrent pacing.  
Verifies shared deferral with a deterministic clock.

## tests/test_reporting_io.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_reporting_io.py`

Tests new-only private outputs, symlinks, commit races, rollback and CLI behavior.  
Preserves other writers and validates complete versus incomplete coverage exit codes.

## tests/test_reporting_model.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_reporting_model.py`

Tests strict imported fields, recomputed counts, snapshots and network consistency.  
Exercises bad schemas, scores, metadata, JSON duplicates, bounds and file kinds.

## tests/test_reporting_renderers.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_reporting_renderers.py`

Verifies inert HTML/CSP, literal terminals, safe Markdown and SARIF mappings.  
Checks no network access, stable identities, null scoring and actual engine progress.

## tests/test_resolver.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_resolver.py`

Parses actual in-memory DNS protocol answers with CNAME records.  
Tests failure behavior without sending DNS traffic.

## tests/test_safety.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_safety.py`

Exercises default ranges, hard blocks, public controls, DNS pinning and audit storage.  
Includes metadata endpoints, IPv6 mappings, scope widening and symlink regressions.

## tests/test_sarif_validation.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_sarif_validation.py`

Tests optional local schema validation and external-reference rejection.  
Uses a minimal owned contract fixture; full official validation is documented separately.

## tests/test_target.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_target.py`

Exercises ambiguous IP and URL inputs, IDNA normalization and CIDR alignment.  
Checks that audit identifiers and object representations omit sensitive URL content.

## tests/test_transport.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_transport.py`

Exercises actual loopback HTTP/TLS/TCP, pinning, redirects, retries and content limits.  
Includes SNI/CA/hostname verification, proxy independence and sensitive logging regressions.

## tests/test_web_discovery.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_web_discovery.py`

HEAD-only exposure controls, XML bounds, disclosure categories and private GET refusals.  
Uses isolated synthetic inputs or ephemeral loopback services without scanning public targets.

## tests/test_web_engine.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_web_engine.py`

All ten checks integrated through the engine and trusted wordlist validation.  
Uses isolated synthetic inputs or ephemeral loopback services without scanning public targets.

## tests/test_web_inputs.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_web_inputs.py`

Benign reflection, baseline SQL signatures, redirect markers and public canary controls.  
Uses isolated synthetic inputs or ephemeral loopback services without scanning public targets.

## tests/test_web_tls.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/test_web_tls.py`

Actual verified/untrusted/date/legacy/NULL-suite handshakes and HTTP trust isolation.  
Uses isolated synthetic inputs or ephemeral loopback services without scanning public targets.

## tests/web_lab.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/web_lab.py`

Provides flexible ephemeral loopback HTTP/TLS routes and locally generated certificates.  
Never binds outside 127.0.0.1; early diagnostic disconnects are expected fixture events.

## tests/web_support.py

Full path: `/workspace/scratch/ef7b82d54654/vuln-scanner/tests/web_support.py`

Constructs scope-approved web contexts and isolated registries for independent checks.  
Uses virtual pacing with real local sockets to bound tests without external DNS.

