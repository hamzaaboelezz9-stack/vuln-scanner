# Command reference

`vulnscan` runs the existing bounded engine. It does not enable a separate or
less-restricted transport. `python cli.py` and `python -m scanner.cli` provide
the same commands from a source checkout. `vulnscan-report` only renders a saved
result; it performs no scan, DNS lookup or advisory update.

## Commands

```sh
vulnscan --version
vulnscan checks --mode web
vulnscan checks --mode net
vulnscan acknowledge
vulnscan web http://127.0.0.1:3000 --checks headers,cookies
vulnscan net 192.168.1.10 --ports 22,80,443 --checks discovery,ports,services
```

On first use, type exactly `I have permission` when prompted. The acknowledgment
is saved, but it does not establish ownership or expand allowed scope. There is
no automatic acceptance flag. On a non-interactive runner, perform the explicit
acknowledgment separately under the same operator-controlled state directory.

## Flags shared by web and net

| Flag | Meaning / default |
| --- | --- |
| `--checks` | Comma-separated built-in names, or `all`; all safe checks by default. |
| `--output` | New report file; with `all`, an exact prefix for `.html`, `.json`, `.md`. |
| `--format` | `html` (default), `json` (SARIF 2.1.0), `md`, `all`. |
| `--result-json` | Additional native `vulnscanner.result.v1` snapshot for offline replay. |
| `--threads` | Workers, default 10; 1–64. |
| `--rate-limit` | Shared operations/second, default 10; includes retries, TCP and TLS. |
| `--timeout` | Absolute per-operation seconds, default 10; 0.05–60. |
| `--scan-seconds` | Shared deadline seconds, default 600; 0.05–3600. |
| `--max-operations` | Attempt cap, default 5000; 1–200000. |
| `--user-agent` | Retain `VulnScanner/` and `authorized-testing-only`; printable ASCII only. |
| `--config` | Validated YAML; `./config.yaml` if present, otherwise built-in defaults. |
| `--allowlist` | Exact scope file; `./allowlist.txt` if present, otherwise empty. |
| `--policy` | Official-provider block snapshot; packaged snapshot by default. |
| `--state-dir` | Private notice/audit state; environment override or `~/.vulnscanner`. |
| `--i-have-permission` | Public-target declaration; exact allowlist and fresh policy still required. |
| `--i-know-what-im-doing` | Separate rate-above-10 declaration; does not change target scope. |
| `--verbose`, `-v` | Include bounded evidence and remediation in terminal output. |
| `--quiet`, `-q` | Terminal findings only; exported coverage stays complete. |
| `--no-color` | Suppress color. Redirected output also omits live progress animations. |

`--quiet` does not suppress a mandatory first-run legal notice or an error.
`--verbose` never enables raw Requests/urllib3 logging or exception tracebacks.
Errors use authored categories so malformed URLs and arguments cannot echo secrets.
Invalid settings, unknown/wrong-mode checks and conflicting report paths are
rejected before reading an acknowledgment or contacting a target. Scope decisions
that reach the gate receive a UUID and an audit event; malformed commands are
not scans and do not create audit records.

## Web-specific flags and coverage

| Flag | Behavior |
| --- | --- |
| `--ca-bundle` | Operator-owned PEM CA bundle. HTTP TLS verification cannot be disabled. |
| `--respect-robots` / `--no-respect-robots` | Conservative robots enforcement; default false. |
| `--weak-tls-probes` / `--no-weak-tls-probes` | Handshake-only legacy diagnostics; default true. |

Built-ins: `headers,cookies,cors,tls,files,xss,sqli,redirect,traversal,disclosure`.
Input checks only inspect a few existing eligible query parameters. They do not
submit forms, crawl recursively or test authentication. A URL without eligible
parameters legitimately skips those checks. Traversal requires an explicitly
configured, owner-created **public non-secret canary**, never `/etc/passwd` or a
private file. HTTP-only targets cannot establish certificate/cipher coverage.
An OPTIONS advertisement is not proof that a write method can be used.

## Network-specific flags and coverage

| Flag | Behavior |
| --- | --- |
| `--ports` | Exact ports/ranges or `common100` / `common1000`; default `common1000`. |
| `--port-db` | Local TCP frequency data for `top100` / `top1000` selection. |
| `--cve-cache` | Prepopulated owner-only NVD catalog. No scan-side online lookup. |

Built-ins: `discovery,ports,services,cves`. These share **one TCP-connect survey**.
No raw SYN, ICMP, UDP or active service commands are sent. Silent peers remain
unknown and are still scanned; open ports are informational inventory. Passive
product strings are advertisements, not verified installed software.

`top100` / `top1000` are compatibility aliases for curated coverage unless a
frequency file is explicitly supplied. `common100` / `common1000` always use
curated data. This avoids a false claim that an authored list is a statistical
popularity ranking. See [network details](NETWORK_CHECKS.md) for the explicit
fixed-publisher cache update command and supported concrete CPEs.

## Reporting and exit codes

```sh
vulnscan web http://127.0.0.1:3000 \
  --output reports/local-review --format all \
  --result-json reports/local-result.json
vulnscan-report reports/local-result.json \
  --output reports/review-copy --format all --no-color
```

Exports are new-only, privately staged and mode 0600 on POSIX. Choose a new
prefix for each run; existing files and symlinks are refused. The native result
and SARIF output must have distinct names. All reports preserve actual UUIDs,
timestamps, minimal evidence, confidence, unscored CVSS and incomplete coverage.

| Exit | Meaning |
| --- | --- |
| `0` | All selected checks completed. Findings may still be present. |
| `1` | Invalid syntax/settings/scope, unavailable state or export failure. |
| `2` | Report produced, but selected coverage is skipped/inconclusive/failed. |
| `130` | Operator interrupted the scan. Running operations cancel cooperatively. |

Coverage codes are not a vulnerability threshold. An empty report is not a
security certification. CI should separately inspect severity and confidence.
