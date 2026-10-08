# Offline reporting

All formats use one validated immutable snapshot. This prevents a HTML report,
console summary and machine-readable export from disagreeing about the same scan.
Reporting is an offline action: it does not authorize or execute a scan, resolve
targets, fetch reference links, load external assets or update the CVE catalog.

## Simple explanation

A finding answers **what was observed**. Coverage answers **what was actually
checked**. If a check fails or cannot run, a scanner cannot honestly call the
application safe just because it recorded no findings. Every report keeps those
two facts separate and shows when manual verification is still needed.

## Modules

| Path | Responsibility |
| --- | --- |
| `scanner/reporting/model.py` | Bounded source validation, immutable snapshot, recomputed summaries and minimal scope/surface data. |
| `scanner/reporting/io.py` | Bounded UTF-8 JSON, duplicate/depth checks, regular-file input and new-only private outputs. |
| `scanner/reporting/console.py` | Rich tables, literal-text fields, compact terminal layout and engine progress adapter. |
| `scanner/reporting/html.py` | Fixed Jinja template, mandatory autoescape and SHA-256 style CSP. |
| `scanner/reporting/templates/` | Authored HTML/CSS with responsive, dark and print layouts. |
| `scanner/reporting/json_export.py` | SARIF 2.1.0 fields and scanner-specific confidence/evidence/coverage extensions. |
| `scanner/reporting/markdown.py` | Escaped prose, isolated evidence blocks and HTTPS references for GitHub issues. |
| `scanner/reporting/export.py` | One/all format rendering from the same snapshot. |
| `scanner/reporting/cli.py` | Installed `vulnscan-report` entry point; existing results only. |
| `examples/validate_sarif.py` | Optional development helper for local official-schema validation without remote reference resolution. |

## Commands

Install the project as described in the README, then:

```bash
python examples/web_checks.py http://localhost:3000 > web-result.json
vulnscan-report web-result.json --output reports/application --format all
vulnscan-report web-result.json --output reports/application.html --format html
vulnscan-report web-result.json --quiet --no-color
python -m scanner.reporting.cli web-result.json --verbose
```

The first command is a scan and requires the existing authorization workflow.
The remaining commands only read the saved result. Choose a fresh output name
for each command: the example HTML destinations are alternatives, not an overwrite
sequence. Version 0.6.0 also provides the full `vulnscan` command and Docker
wrapper described in [CLI.md](CLI.md) and [DEPLOYMENT.md](DEPLOYMENT.md).

On PowerShell, an installed command is also available as:

```powershell
.\.venv\Scripts\vulnscan-report.exe docs\WEB_SAMPLE.json --output reports\web-review --format all
```

`-` as the input reads binary stdin. `--quiet` limits console presentation to
findings; it does not omit coverage or evidence from exported files. `--verbose`
adds bounded descriptions/evidence/remediation to console output. `--no-color`
disables terminal colors. File formats are `html`, `json`, `md` or `all`.

With `--format all`, `reports/review.v1` produces `review.v1.html`,
`review.v1.json` and `review.v1.md`. The exact prefix is retained, including any
suffix. Without `all`, `--output` is the exact output filename.

| Exit | Meaning |
| --- | --- |
| 0 | Input/export succeeded; all recorded selected checks completed and the scan has an end time. |
| 2 | Input/export succeeded; coverage is partial, absent or unfinished. |
| 1 | Input/schema/filesystem/export error; review the categorized diagnostic. |
| 130 | Interrupted by the operator. |

Findings and their severity do not change exit codes. This matches the existing
example scanners; CI policies should examine severity **and** confidence.

## Python API

```python
from pathlib import Path

from scanner.reporting.console import ConsoleReporter
from scanner.reporting.export import export_report
from scanner.reporting.model import ReportDocument

# result is the ScanResult returned by the existing authorized ScanEngine.
document = ReportDocument.from_result(result)
ConsoleReporter().render(document)
export_report(document, Path("reports/assessment"), "all")
```

For an existing result file:

```python
from pathlib import Path
from scanner.reporting.io import load_result
from scanner.reporting.html import render_html

document = load_result(Path("web-result.json"))
html_text = render_html(document)
```

To connect the existing engine's progress callback:

```python
reporter = ConsoleReporter()
with reporter.progress() as progress:
    result = engine.run(target, progress=progress)
reporter.render(ReportDocument.from_result(result))
```

These integration fragments require the caller's already constructed authorized
engine/target/result; executable complete examples are in `examples/`. Progress
counts **settled checks**, including failures; it does not imply passed checks.
Bars are disabled for non-terminal output. Only a fixed authored description
enters the Rich progress markup parser.

## Source-result validation

Input is the existing `vulnscanner.result.v1` JSON, including the example runners'
optional `purpose` metadata. Other schemas, invalid timestamps, inconsistent
CVSS vectors/scores and impossible network summaries fail closed. A nullable
end time is accepted but remains unfinished. Imported summary `counts` are
ignored and recomputed from findings. Unknown properties are discarded rather
than forwarded to output. Scope declarations are never evidence of permission.

Limits are explicit: 16 MiB input, 16 levels of JSON nesting, 200,000 JSON nodes,
2,048 findings, 64 outcomes, 4,096 approved addresses, 1,000 approved ports and
1,024 records each for open/uncertain ports. Oversized lists fail rather than
silently dropping findings. Raw banners are never accepted as report properties.
Built-in checks fit these bounds; custom trusted plugins may need a separate
bounded export policy. Output files are capped at 32 MiB each.

## JSON / SARIF contract

`--format json` exports SARIF **2.1.0**, not the source-result v1 JSON. It uses:

- `runs[0].tool.driver`: name, release version and unique rule descriptors.
- `runs[0].results`: `ruleId`, matching `ruleIndex`, standard level/kind,
  description, SHA-256 stable partial fingerprint and optional endpoint URI.
- `results[i].properties`: original severity/confidence, minimal evidence,
  remediation, references and nullable CVSS object.
- `runs[0].properties.vulnscanner`: original scan ID/time, declared scope,
  coverage/outcomes, counts, operations/limits and bounded attack surface.

Critical/high map to `error`; medium/low to `warning`; informational to `note`.
Confidence remains an explicit property. Informational results use SARIF
`kind: informational`; other indicators use `kind: fail` but **do not imply
confirmed exploitation**. Consumers must use the confidence property.
Dynamic endpoints have no invented code filename or source line. There is no
`security-severity` default inferred from missing CVSS. Advisory scores stored
inside evidence remain catalog metadata, separate from target CVSS.

The schema URL in `$schema` is descriptive and never fetched by reporting.
These dynamic scan reports are not a promise of GitHub code-scanning acceptance:
GitHub may require source-code/repository locations and additional constraints.
Markdown exports can be pasted into issues after operator review; this tool
does not create issues or send reports.

For an independent offline schema check, obtain the official schema on a machine
with normal HTTPS access, review it, and pass the local file to the helper:

```bash
curl --fail --location --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json \
  --output sarif-schema-2.1.0.json
python examples/validate_sarif.py reports/application.json --schema sarif-schema-2.1.0.json
```

`jsonschema` is a development dependency. The validator refuses external `$ref`,
`$dynamicRef` and `$recursiveRef`; only internal fragment references are allowed.
It validates structure/formats, not target truth or authorization. The helper
accepts trusted local report/schema paths; it is not a sandbox for hostile custom
schemas or special device paths. Validation results are categorized without
echoing raw findings. The schema is not bundled or fetched by tests.

## Output security decisions

- **HTML:** Jinja autoescaping is always enabled with `StrictUndefined`. Fixed
  packaged templates are never generated from source text. Only authored CSS
  is marked as trusted markup. The exact CSS bytes get a SHA-256 CSP hash;
  scripts, connections, fonts, images, objects, forms and base URLs are blocked.
  No JavaScript, inline event handlers, `unsafe-inline`, CDNs, telemetry or remote
  assets exist. HTTPS reference links require explicit operator clicks and use
  `noopener noreferrer`; endpoints remain text. Print layout uses native browser
  printing, without a PDF service.
- **Terminal:** target-controlled content always uses literal `Text` renderables.
  ANSI/OSC controls and bidirectional format characters are removed before
  rendering. Rich colors are applied only from fixed severity mappings.
- **Markdown:** prose escapes raw HTML, Markdown delimiters and mention syntax.
  Evidence stays in a dynamically lengthened code fence, so embedded backticks
  cannot escape it. HTTPS reference paths are quoted, with userinfo/query/fragment
  removed. No raw HTML layouts or executable preview scripts are used.
- **Privacy:** known secret assignments/JWTs and HTTP query values are redacted
  again at the report boundary. Unknown result properties are discarded. Redaction
  is not a universal secret detector: arbitrary prose, path segments or operator
  metadata can still contain secrets. Review every report before publishing.
- **Filesystem:** complete reports are staged as owner-only temporary files,
  flushed, then linked to new paths atomically. Existing files/symlinks are never
  overwritten. New directory mode is 0700 and file mode 0600 on POSIX. Three-file
  publication uses best-effort rollback rather than a filesystem transaction;
  interruptions or cleanup failures can leave private staged files or partial
  output. Use an operator-controlled destination directory. Symlink preflight
  is not protection against a malicious process replacing parent directories.
  Filesystems without hard links fail closed. Windows ACL behavior is untested.

HTML's meta CSP cannot set HTTP-only `frame-ancestors`. If serving reports over
HTTP, enforce authorization and set server response headers such as
`Content-Security-Policy: frame-ancestors 'none'` and `X-Content-Type-Options: nosniff`.
Do not publicly host sensitive reports. Local snapshots are not signed or tamper
evident, and a malicious local writer can falsify reported data or alter the HTML.

## Samples and verification

`docs/reports/web-assessment.*` and `network-assessment.*` were generated offline
from the existing measured Phase 3/4 synthetic loopback results. They preserve
the original scan IDs/timestamps/operations/coverage and clearly identify
synthetic provenance. No new public scan, live CVE finding or Juice Shop report
is invented. The files are safe example metadata for repository review.

See [VALIDATION.md](VALIDATION.md) for the actual checks and platform limits.

## Primary references

- [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
- [Official SARIF schema repository](https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json)
- [Jinja environment and autoescaping](https://jinja.palletsprojects.com/en/stable/api/)
- [Rich literal Text API](https://rich.readthedocs.io/en/stable/reference/text.html)
- [CSP style-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/style-src)

## Full scanner CLI integration

`vulnscan web` / `vulnscan net` consume the same validated snapshot, preflight
all destination names before target traffic and publish three reports plus an
optional native JSON result in one private staging operation. `render_reports`
prepares format strings without filesystem mutation; `write_reports` handles
new-only publication. JSON report output is SARIF, while `--result-json` retains
the native schema for later `vulnscan-report` replay. Maximum publication count
is four, and rollback remains best effort.

The `cli-assessment.*` sample comes from `CLI_SAMPLE.json`, a real v0.6.0 installed
CLI run against an owned synthetic loopback application. Its header/cookie
signals, UUID and times are measured; the public context label was annotated
offline. It is separate from the earlier Phase 3/4 samples and from Juice Shop.
