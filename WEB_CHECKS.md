# Phase 3 web rules and evidence contract

This release performs anonymous, bounded detection against approved origins.
It does not establish exploitability from response keywords alone. A complete
check means its declared probes completed, not that every vulnerability class
or endpoint was tested. Automated detection is one input to an authorized review.

## Rule selection and boundaries

Explicitly call `load_web_checks()` before `ScanEngine.run()` or use
`examples/web_checks.py`. `--checks headers,cookies` selects known registered
names. Unknown/duplicate names fail before target traffic. Importing modules
only registers classes; it does not resolve targets or start scans.

| Class / name | Probes | Evidence and interpretation |
| --- | --- | --- |
| HeadersCheck / headers | Header-only GET and OPTIONS. | Missing/inactive HSTS on named HTTPS hosts; CSP/framing/MIME/referrer/permissions controls; advertised PUT/DELETE/TRACE. These verbs are never sent. Restrictive frame-ancestors can replace X-Frame-Options. Missing optional hardening is informational or low risk. |
| CookiesCheck / cookies | Independent Set-Cookie headers from header-only GET. | Flag/prefix categories and response line numbers, never names/values. Cookie purpose is unknown. Missing SameSite does not disable modern default Lax protection. Ambiguous duplicate/malformed attributes produce incomplete coverage. |
| CorsCheck / cors | GET with two fresh .invalid origins and null; OPTIONS GET preflight. | Reflection is a potential issue, not proof of credentialed data access. Wildcard plus credentials is invalid browser configuration: browsers block credentialed reads. Null trust and missing Vary need contextual review. |
| TLSCheck / tls | Header-only HTTP counterpart and public TLS handshakes. | Verified trust failures and public certificate dates; actual deprecated/weak negotiation. Configured CA matters for private PKI. Handshake diagnostics never send application bytes. |
| FilesCheck / files | Twelve curated sensitive paths via HEAD with randomized same-directory/extension HEAD controls; bounded public directory/robots/sitemap GET. | Non-HTML 200 versus 404/410 is a candidate requiring owner verification. No sensitive content or linked inventory URLs are downloaded. Admin response is informational. Directory-index structure does not establish file sensitivity. |
| XSSCheck / xss | Baseline HTML and one inert marker with quotes/angles/ampersand per eligible field. | Literal metacharacter reflection is potential unsafe output, not executed XSS. Encoded HTML or JSON is not flagged as HTML reflection. No executable script/event payload is generated. |
| SQLiCheck / sqli | Baseline and exactly one appended single quote per eligible field. | New DB-error signature families indicate a parser/error-handling signal, not confirmed injection. Existing baseline errors are excluded. No Boolean/UNION/time probes, authentication bypass or data extraction. |
| RedirectCheck / redirect | Existing redirect query fields changed to fresh https .invalid destinations. | A 3xx Location with the exact marker hostname confirms externally controllable redirect behavior. Intentional redirect policy and business impact need review. Destination is never followed/resolved. |
| TraversalCheck / traversal | Explicit public canary, missing/basename controls, one ../ prefix. | Exact differential is potential traversal/normalization behavior. It does not prove filesystem escape. Disabled without configured owner-created public fixture. No OS/private filenames are generated. |
| DisclosureCheck / disclosure | Public page, one missing-page control, first four scoped public script candidates, source-map HEAD with missing controls. | Header names, generator presence, comment/error categories and candidate map metadata. Raw versions, comments, traces, scripts and map/source contents never enter findings. A matching documentation page may be a false positive. |

Each rule includes description, minimal method/status observations, remediation
and primary OWASP/CWE references. No framework is inferred from a spoofable
banner. Fixes are framework-independent when the application stack is unknown.

## Input eligibility

Active input rules use only query parameters already in the supplied URL.
They preserve duplicate occurrence order, bound parsing to 32 fields, and inspect
the first four applicable fields. They never discover/invent parameters or submit
forms. Authentication/secret-like names, action fields, and named login/write
routes cause active rules to skip before traffic. Conservative exclusions can
miss legitimate searchable fields such as `zipcode`; this is deliberate.

Passive checks can still inspect the supplied public endpoint. Operators must
select a side-effect-free URL. A badly designed application's GET or OPTIONS can
change state despite HTTP semantics; the tool cannot prove arbitrary route safety.
Do not supply password/token/session-bearing query URLs or production secrets.

## Public traversal canary setup

This feature is optional and needs cooperation from the application owner.
Place a new, **non-secret** static file in the intended public document root.
Generate its constrained name and token locally:

```bash
python -c 'import secrets; print("/vulnscanner-canary-" + secrets.token_hex(16) + ".txt"); print("vulnscanner-canary-" + secrets.token_hex(16))'
```

The first output is the public path; the second must be the file's entire
content (a trailing newline is accepted). Set both corresponding YAML fields
using the generated outputs, then supply an existing `file`, `path`, `filename`,
`document`, `template` or `download` query field on a read-only endpoint.
The path must be `/vulnscanner-canary-<16–64 hex>.txt`; the token must be
`vulnscanner-canary-<16–96 ASCII letters/digits/underscore/hyphen>`.

The exact static token is first verified. Only the same basename with a single
parent prefix is submitted, together with controls. A generic response serving
the canary for every input is not evidence. Findings omit the token, and exported
settings omit both canary fields. Remove the public fixture after testing.
**Never substitute /etc/passwd, keys, secrets or private application files.**

## TLS detail and limits

All HTTPS requests authenticate the original hostname against the configured
CA bundle using TLS 1.2 or newer. A trust failure is not silently retried using
insecure HTTP. Dedicated diagnostic profiles use separate OpenSSL contexts with
CERT_NONE solely to collect public certificate/handshake metadata; they have
no application-data send interface and do not modify the HTTP context.

Fixed TLS 1.0 and 1.1 profiles require successful negotiation to report support.
The weak-suite profile offers locally available NULL/anonymous/export/DES/3DES/
RC4 suites under TLS 1.2. Modern OpenSSL often disables older suites entirely.
Unavailable profiles and incomplete legacy families are recorded; a handshake
rejection is not proof that all combinations are rejected. No full cipher census,
revocation/OCSP assurance, vulnerability exploitation or every-chain-path analysis
is claimed. Verified OpenSSL trust checks the presented chain under local policy.
Certificates collected diagnostically are explicitly labeled unverified.

HTTP enforcement uses the approved same-host counterpart. Standard ports map
80/443; custom ports stay the same. A TLS-only custom port usually cannot answer
plain HTTP: that coverage remains incomplete, independent of certificate results.
The HTTPS redirect destination is inspected, never followed for this rule.
HSTS is assessed separately in the headers rule and skipped for numeric hosts.

## Evidence, scores and coverage

Severity is a conservative triage judgment independent of confidence. These
anonymous rules leave `cvss: null`: prerequisites, affected data and exploit impact
are unknown. The tested CVSS v3.1 module accepts full justified vectors when an
assessor has verified impact. Numeric scores are never fabricated from keywords.

Findings retain endpoint paths and query **names**, with values redacted. Raw
bodies, cookie/header values, markers, canary tokens and stack traces are omitted.
Public script/page bytes exist briefly in process memory; Python does not promise
secure zeroization. The local audit log stores the target origin and authorization
metadata rather than paths or queries. Protect reports and avoid sensitive URL
path segments; regex redaction cannot identify all secret forms.

Robots/sitemap analysis stores reference counts and approved-scope counts, not
hidden URL values. Public source maps and .env/backup candidates are HEAD-only.
Unsupported HEAD and soft 404/200 rewrites remain inconclusive; there is no GET
fallback. A transport guard rejects GET for known private patterns, even through
redirects, but cannot classify all possible private files.

Checks keep established findings if a later expected operation fails. Truncation,
compressed/unavailable content, ambiguous controls, local TLS restrictions and
operation/deadline limits remain visible in coverage. The shared pacer counts
all attempts, including retries and handshakes. Empty findings with skipped or
inconclusive checks are not a security pass.

## Reproduce the measured local sample

```bash
python -m tests.generate_web_sample --output docs/WEB_SAMPLE.json
```

Run from an installed source checkout with runtime dependencies. The harness
creates an ephemeral listener bound only to 127.0.0.1, synthetic routes, temporary
operator state and YAML, then launches the shipped web runner using real pacing.
The sample contains observed UUID/timestamps/port/findings. It is explicitly
labeled an artificial fixture, **not an OWASP Juice Shop scan**. New executions
have different metadata and may reflect local TLS capabilities. No public scan
or real credentials are involved.
