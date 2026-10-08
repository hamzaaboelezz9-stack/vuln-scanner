# Phase 4 network checks

A TCP connect asks whether an approved address/port will accept a connection.
The scanner then closes it, or briefly listens for a greeting. Think of it as
calling a listed number and recording whether it answers, refuses, or stays
silent. Silence does not prove the host is absent. A greeting is an advertisement,
not proof of who owns or patched the service.

## Delivered modules

| Module / check | Responsibility |
| --- | --- |
| core/network.py | Validated connection, greeting and advertised-service data models. |
| network/survey.py | One shared survey, rolling concurrent jobs, bounded memory and deterministic results. |
| network/discovery.py / discovery | Open/refused TCP-response inventory; middlebox and unknown-host caveats. |
| network/ports.py / ports | Open listener inventory with separate refusal/timeout/unreachable/error counts. |
| network/services.py / services | Passive greeting signatures; no active service/authentication commands. |
| network/cves.py / cves | Read fresh local NVD candidates, with manual applicability verification. |
| utils/ports.py | Strict exact/range selections, curated lists and operator-supplied frequency ranking. |
| utils/fingerprints.py | Constrained protocol/product/version extraction and concrete CPE mapping. |
| utils/cve.py | Compact private cache and separate fixed-publisher NVD update command. |

`load_network_checks()` explicitly imports the four decorated classes; imports
perform no scanning. The engine creates one `NetworkSurvey` after authorization.
The first check needing its results collects; others await the same immutable
records. Every host/port pair gets **one** counted TCP-connect attempt, and service
identification uses that same connection. The shared operation/rate/deadline
controller applies across the entire survey. A port-only selection skips greeting
waits. A CVE-only selection without a configured cache skips before connections.

The outer engine workers supervise checks; one rolling survey pool performs
at most `workers` concurrent TCP operations. Only `workers` jobs are outstanding,
rather than allocating a future for every possible pair. Every pair is permitted
again immediately before dialing its numeric address. Discovery never excludes
hosts from later port probes because an earlier response was missing.

## Run the example

From an installed source checkout, against a system you own:

```bash
python examples/network_checks.py 127.0.0.1 --ports 22,80,443
python examples/network_checks.py 127.0.0.1 --ports 8000-8010 --checks discovery,ports
python examples/network_checks.py 192.168.1.0/28 --ports common100
```

The first run requires the saved exact notice acknowledgment. Local/private
addressing does not prove permission. Public targets still require an exact
allowlist, explicit permission flag, fresh provider policy and all hard blocks.
DNS aliases and all returned addresses are approved before service traffic.
Named targets survey every approved numeric address, rather than silently testing
only the first DNS answer. Only supplied ports are approved; unrelated hosts,
ports and metadata services remain blocked.

The runner accepts checks, YAML, allowlist, policy, state directory, port database,
CVE-cache directory, threads/rate/timeout overrides and the separate permission
flags. It emits sanitized JSON to stdout; the legal notice goes to stderr.
Exit **0** means all selected check coverage completed, **2** means some coverage
was skipped/inconclusive/failed, **1** is a setup/authorization error and **130**
is interruption. Finding counts are separate from completion status. The full
colored CLI and HTML/Markdown/SARIF-lite reports are the next phase.

## Port selection and scale

At most **1000 distinct ports** are selected per scan. Exact lists and ascending
ranges are strict: duplicate/overlapping selections, port zero, malformed ranges
and excessive counts are refused. `common100` and `common1000` are independently
curated coverage sets. They include common application ports; the larger set then
covers low system ports. They are **not a statistical ranking**.

`top100`/`top1000` are compatibility aliases: without `--port-db`, they use those
curated sets and disclose that basis in output. For actual frequency-ranked
selection, explicitly supply your installed Nmap data:

```bash
python examples/network_checks.py 127.0.0.1 --ports top1000 --port-db /usr/share/nmap/nmap-services
```

Only TCP rows with validated finite frequencies are ranked. UDP rows are ignored.
The database is bounded to 4 MiB/50,000 lines and must contain enough distinct TCP
ports. This project does not ship Nmap's third-party dataset or label synthetic
frequencies as measurements. Nmap is optional, not a runtime scanning dependency.
Port assignments do not establish service identity; see the IANA registry.

The authorized `addresses × ports` matrix must fit the configured scan-operation
budget before target connections. Defaults permit 5000 attempts, 256 total CIDR
addresses, 10 operations/sec and a 600-second scan deadline. A /24 with 1000 ports
exceeds even the maximum 200,000-operation budget; choose smaller explicit batches.
Increasing limits does not bypass authorization or the separate aggressive-rate
permission. At 10/sec, 1000 connections need at least about 100 seconds even when
responses are immediate. Timeouts can add coverage gaps. Raising threads does
not raise the global rate.

## Observations and coverage

The network matrix distinguishes:

- `open`: TCP connect succeeded.
- `connection-refused`: the OS reported refusal, possibly from an intervening filter.
- `no-response`: a timeout, not a closed/dead assertion.
- `unreachable`: the OS reported no reachable network/host path.
- `local-or-transport-error`: a different error, without retaining its text.

`attack_surface` adds per-host state counts, planned/observed pair counts and
bounded open/uncertain port records. Up to 1024 records of each type are retained;
omitted counts remain explicit. Unknown or unattempted pairs are never labeled
closed. Each check outputs at most 256 findings, with an explicit output-cap
coverage note. A failed worker/resource is failed coverage, distinct from silence.
Cancellation stops new jobs and preserves completed observations; socket deadlines
bound in-flight work. All built-in survey application-byte counts are zero.

Open ports are informational inventory, not vulnerabilities. Banner identities
remain unverified. All target finding CVSS values are null until an assessor has
verified the required impact and prerequisites. A CVE candidate can quote a
validated **published catalog** vector/base score without asserting that it scores
the observed target. Candidates remain informational pending manual review.

## Passive fingerprints

Bounded authored signatures recognize OpenSSH, Dropbear, vsftpd, ProFTPD and Exim
advertisements, plus generic SSH/FTP/SMTP/POP3/IMAP/RFB and complete MySQL-compatible
greetings. Only constrained identifiers/version tokens enter reports. Distribution
suffixes, raw greeting lines, salts, arbitrary welcome text and potential secrets
are omitted. RFB's protocol revision is not a software version. MySQL-compatible
identity does not establish Oracle/MariaDB vendor applicability.

The read window defaults to 0.5 seconds (configurable 0.05–5), within the absolute
operation/scan deadline; at most 4096 greeting bytes are retained transiently.
Fragmented greetings are accumulated through a line/EOF/bound. Incomplete or
unrecognized greetings leave service coverage incomplete. HTTP, HTTPS, Redis and
many other services do not send a useful spontaneous greeting, so they often
remain unknown. Use the separately approved web mode for HTTP. No login, HEAD
request, database command, authentication negotiation or exploit payload is sent
to an unidentified network listener. This phase uses standard TCP connects, not
privileged raw SYN, ICMP, UDP or OS-fingerprint probes.

## Explicit NVD cache workflow

Scans never contact NVD automatically. Configure `cve_cache` or `--cve-cache`
only after populating the cache for a supported concrete product CPE:

```bash
python -m scanner.utils.cve --cpe 'cpe:2.3:a:openbsd:openssh:9.8:p1:*:*:*:*:*:*' --cache-dir /path/to/private-nvd-cache
python examples/network_checks.py 127.0.0.1 --ports 22 --cve-cache /path/to/private-nvd-cache
```

The first command is a separate **public catalog** update. It contacts only the
fixed NVD CVE API over verified HTTPS, with bounded DNS, numeric dialing, original
hostname verification, TLS 1.2+, an absolute 15-second I/O deadline, capped headers
and a 2 MiB identity-encoded JSON response. It has no implicit proxy, cookies,
credentials, redirect, retry, target address or full greeting. Only the operator's
concrete public product CPE is transmitted. Publisher fetching is deliberately
separate from target-scanning scope; it cannot be given an arbitrary URL/hostname.
Local/metadata publisher resolutions are refused. Proxy-only environments need
ordinary direct publisher access; the updater does not inherit ambient proxies.

Each invocation can refresh at most ten queries and spaces them at least 6.1
seconds apart, conservatively matching NVD's public request budget. Separate
operator invocations are not cross-process rate coordinated. Stop/retry later on
publisher throttling; a failed update preserves the existing valid entry.

The query uses `cpeName`, `isVulnerable`, `noRejected`, `startIndex=0` and a bounded
100-result page. Pagination is explicit incomplete coverage. NVD performs range
matching; the tool does not invent its own version-range comparator. Cache files
retain only query identity, source, UTC capture time, CVE IDs and validated 3.1
vectors, under private directory/file permissions (700/600 on tested POSIX).
Symlinks/special files, absent/stale (>7 days), future-dated or mismatched entries
are refused. API responses must match their vectors' recalculated scores.

OpenSSH portable updates are mapped separately (`9.8p1` → `9.8:p1`), as are supported
ProFTPD letter releases. Other unsupported CPE mappings remain unknown. At most
five advisories per service are displayed; additional candidates/pages stay
visible as limits. Spoofed banners, distro backports, client-only advisories,
module/environment conditions and missing NVD enrichment all need owner review.
An empty cache result is not proof of patching or freedom from vulnerabilities.

## Reproduce the local sample

```bash
python -m tests.generate_network_sample --output docs/NETWORK_SAMPLE.json
```

The harness binds two ephemeral servers exclusively to 127.0.0.1, uses simulated
SSH/SMTP greetings and one closed port, then runs the shipped example with actual
default pacing and temporary acknowledged state. UUID/timestamps/ports/results
are measured. It verifies one connection per open listener and no application
commands. The sample has no live NVD lookup or invented installed-version/CVE
claim; it is not Juice Shop or a production assessment.

## Primary references

- [Python socket timeouts](https://docs.python.org/3.10/library/socket.html)
- [Python errno classifications](https://docs.python.org/3.10/library/errno.html)
- [IANA service/port registry](https://www.iana.org/assignments/service-names-port-numbers/)
- [Nmap port-scanning overview](https://nmap.org/book/port-scanning.html)
- [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities)
- [NVD public API practices](https://nvd.nist.gov/developers/start-here)
- [NVD OpenSSH 9.8 portable CPE](https://nvd.nist.gov/products/cpe/detail/5bc54669-2bfd-43de-86ac-34bc61722d31)
