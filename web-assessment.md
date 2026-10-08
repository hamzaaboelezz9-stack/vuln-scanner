# VulnScanner security assessment

**Target:** http://127\.0\.0\.1:45301  
**Scan ID:** a67970bb-deed-4637-aff4-d3a043ba1f00  
**Mode:** web | **Coverage:** Partial / unfinished

## Executive summary

22 findings recorded; highest reported severity: Medium\. 9 of 10 selected checks completed\. 9 findings need manual verification\. Automated observations do not establish exploitability, compliance or complete security\.

**Provenance:** Measured synthetic loopback web fixture; not OWASP Juice Shop or a production assessment\.

| Severity | Count |
| --- | ---: |
| Critical | 0 |
| High | 0 |
| Medium | 6 |
| Low | 10 |
| Info | 6 |

## Scope and coverage

Scope is declared in the source result; this report does not independently verify permission.

**Started (UTC):** 2026-10-06T12:54:54.775305+00:00  
**Ended (UTC):** 2026-10-06T12:55:01.097752+00:00

| Check | Outcome | Explanation |
| --- | --- | --- |
| cookies | complete | Completed selected check |
| cors | complete | Completed selected check |
| disclosure | complete | Completed selected check |
| files | complete | Completed selected check |
| headers | complete | Completed selected check |
| redirect | complete | Completed selected check |
| sqli | complete | Completed selected check |
| tls | inconclusive | Verified TLS did not negotiate; certificate trust could not be established\. Public TLS certificate metadata was unavailable\. Locally disabled RC4/DES/3DES/export suites cannot be exhaustively tested; weak\-cipher coverage is partial\. |
| traversal | complete | Completed selected check |
| xss | complete | Completed selected check |

**Declared approved addresses:**

```text
127.0.0.1
```

**Declared approved ports:**

```text
45301
```

**Operations:** HTTP=59, TCP=0, TLS=5

## Attack surface

Network inventory was not supplied. Web coverage is limited to the recorded target and selected checks.

## Findings

### FINDING-001: Credentialed null Origin is accepted

**Rule:** cors\.null\_origin  
**Severity:** Medium | **Confidence:** needs-manual-verification  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

Sandboxed/non\-hierarchical origins can serialize to null\. Sensitive credentialed impact remains unverified because no authenticated request was made\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Origin null was accepted with credential allowance true.
```

**Remediation:**

Reject null origins on private resources; use an explicit trusted origin allowlist and justify any public null\-origin access\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [Reference 2](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin)

### FINDING-002: Arbitrary Origin reflection observed

**Rule:** cors\.reflected\_origin  
**Severity:** Medium | **Confidence:** needs-manual-verification  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

Two independent reserved origins were echoed\. Credentialed private\-data impact depends on authenticated endpoints, cookies and browser behavior; \[Needs manual verification\]\. Uncredentialed public endpoints may intentionally allow this\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Two random Origin values were echoed exactly.
Credential allowance: true
No cross-origin destination was contacted and no credentials were sent.
```

**Remediation:**

Match serialized origins against an exact trusted allowlist\. Reject unknown/null origins for private resources, enable credentials only where needed, and include Vary: Origin on dynamically selected origins\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [Reference 2](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin)

### FINDING-003: Sensitive\-file URL returned distinct success metadata

**Rule:** files\.sensitive\_candidate  
**Severity:** Medium | **Confidence:** needs-manual-verification  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

A curated sensitive\-file path returned HTTP 200 while its randomized same\-directory/extension control returned not\-found\. No file content was downloaded, and private\-data exposure is unconfirmed; \[Needs manual verification\]\.

**Evidence:**

```text
HEAD http://127.0.0.1:45301/.env
HTTP status: 200
HEAD candidate returned 200; corresponding nonexistent control returned 404.
Non-HTML metadata observed. File contents, credentials and private data were not retrieved.
```

**Remediation:**

Remove config, repository, database and backup files from public document roots\. Deny dotfiles/config extensions in Nginx or Apache and store backups outside served directories\. Have the owner verify the candidate before rotating any credentials\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information)

### FINDING-004: Query parameter controls an external HTTP redirect

**Rule:** input\.open\_redirect  
**Severity:** Medium | **Confidence:** confirmed  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

A unique reserved\-domain marker supplied in an existing query field became the external Location destination of a redirect response\. This establishes externally controlled redirect behavior; business impact and intentional redirect policy need review\. The destination was never resolved or contacted\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 302
Existing query field inspected: next
A unique reserved-domain marker became the redirect hostname.
Redirect following was disabled; no external service was contacted.
```

**Remediation:**

Allow only approved relative paths or exact trusted origins\. Parse and compare canonical scheme/host/port rather than substrings; reject scheme\-relative destinations and credentials\. For intentional external links, use a clear interstitial and avoid sensitive tokens in URLs\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect)
- [Reference 2](https://cwe.mitre.org/data/definitions/601.html)

### FINDING-005: Single quote introduced a database parser\-error signal

**Rule:** input\.sql\_error  
**Severity:** Medium | **Confidence:** needs-manual-verification  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

A database syntax\-error signature appeared after a single\-quote mutation and was absent from the baseline\. This may reflect unsafe query construction or diagnostic handling; SQL injection and its impact are not confirmed\. No query logic, data extraction or authentication bypass was attempted\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Existing query field inspected: id
New signature families: MySQL syntax error
A single quote was appended; raw error text and data were omitted.
```

**Remediation:**

Use parameterized queries/prepared statements for all values; validate identifiers with explicit allowlists\. Disable database exception details in client responses and review the affected query construction in source or an owned test environment\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [Reference 2](https://cwe.mitre.org/data/definitions/89.html)

### FINDING-006: Parent\-relative input returned the public canary

**Rule:** input\.traversal\_canary  
**Severity:** Medium | **Confidence:** needs-manual-verification  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

A parent\-relative filename returned the exact operator\-supplied public canary where basename and missing controls did not\. Filesystem escape and the application&\#x27;s intended boundary require manual verification\. No operating\-system or private file was requested\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Existing query field inspected: file
Exact public-canary differential observed; token and file contents were omitted.
Only a single ../ prefix and the approved public canary filename were used.
```

**Remediation:**

Resolve paths against an explicit allowed base directory and reject any canonical result outside that base\. Prefer opaque file IDs to filenames, reject absolute/dot\-segment paths, and authorize every requested object\. Verify the intended boundary using this non\-secret canary\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)
- [Reference 2](https://cwe.mitre.org/data/definitions/22.html)

### FINDING-007: Cookie security attributes need review

**Rule:** cookies\.attributes  
**Severity:** Low | **Confidence:** needs-manual-verification  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

Observed cookie attributes may be unsuitable for authentication cookies\. Non\-sensitive or intentionally script\-readable cookies may legitimately differ; \[Needs manual verification\]\. Missing SameSite does not disable modern browsers&\#x27; default Lax behavior\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Set-Cookie line 1: Secure absent; HttpOnly absent; SameSite absent or invalid
Cookie name and value were omitted.
```

**Remediation:**

For session cookies, set Secure, HttpOnly and an appropriate SameSite=Lax/Strict policy\. SameSite=None requires Secure\. For \_\_Host\- cookies, use HTTPS, Secure, Path=/ and no Domain\. Do not set HttpOnly on deliberately script\-readable anti\-CSRF tokens\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes)

### FINDING-008: Dynamic CORS origin lacks Vary: Origin

**Rule:** cors\.vary  
**Severity:** Low | **Confidence:** observation  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

A reflected\-origin response did not advertise Origin variation\. Actual cache confusion depends on response cacheability and infrastructure\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Dynamic origin selection observed without consistent Vary: Origin.
```

**Remediation:**

Add Vary: Origin to dynamic CORS responses and review intermediary cache keys and private\-response caching\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [Reference 2](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin)

### FINDING-009: HTML comment contains a sensitive\-information signal

**Rule:** disclosure\.comment  
**Severity:** Low | **Confidence:** needs-manual-verification  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

A bounded comment matched a sensitive\-information category\. It may be a dummy value or documentation; \[Needs manual verification\]\. Comment content and potential secrets were not retained\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Matched category: secret-assignment-like text
Comment text and values were omitted.
```

**Remediation:**

Remove secrets/internal deployment details from served HTML, including comments\. Have the owner verify the signal and rotate any confirmed exposed credentials\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage)

### FINDING-010: Source\-map URL returned distinct success metadata

**Rule:** disclosure\.source\_map  
**Severity:** Low | **Confidence:** needs-manual-verification  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

A referenced or conventional source\-map URL returned non\-HTML success distinct from a not\-found control\. Map contents, embedded source and private data were not downloaded; \[Needs manual verification\]\.

**Evidence:**

```text
HEAD http://127.0.0.1:45301/app.js.map
HTTP status: 200
HEAD map candidate succeeded while its randomized control was not found.
No source-map body or embedded source code was retrieved.
```

**Remediation:**

Omit public source maps containing private source/configuration from production builds, or serve them only to an authenticated debugging service\. Public maps with intentionally public source may be acceptable\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage)

### FINDING-011: Directory listing structure observed

**Rule:** files\.directory\_index  
**Severity:** Low | **Confidence:** confirmed  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

The response contains a conventional directory\-index heading and multiple links\. This establishes an index\-style response; the sensitivity of listed files is unverified\. No linked file was downloaded\.

**Evidence:**

```text
GET http://127.0.0.1:45301/uploads/
HTTP status: 200
Conventional directory-index heading and at least two links were observed.
Listed filenames and response contents were omitted.
```

**Remediation:**

Disable Nginx autoindex or Apache Options Indexes for non\-public directories\. Keep non\-public files outside the web root and authorize deliberate file listings\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information)

### FINDING-012: Enforcing Content Security Policy is absent

**Rule:** headers\.csp  
**Severity:** Low | **Confidence:** observation  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

This HTML response lacks a header\-enforced CSP\. CSP is defense in depth; absent CSP alone does not establish XSS\. A meta\-delivered policy has not been inspected by this header\-only rule\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
No enforcing Content-Security-Policy header was observed.
```

**Remediation:**

Deploy a tested CSP with nonce/hash\-based script sources, object\-src &\#x27;none&\#x27;, base\-uri &\#x27;self&\#x27;, and frame\-ancestors &\#x27;none&\#x27; or a justified allowlist\. Use report\-only during rollout, then enforce\.

**References:**

- [Reference 1](https://owasp.org/www-project-secure-headers/)

### FINDING-013: No restrictive framing header was observed

**Rule:** headers\.framing  
**Severity:** Low | **Confidence:** observation  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

Neither a valid X\-Frame\-Options policy nor a structurally restrictive CSP frame\-ancestors directive was observed\. Actual clickjacking impact needs manual verification\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
No supported restrictive framing control was found in response headers.
```

**Remediation:**

Set CSP frame\-ancestors &\#x27;none&\#x27; or &\#x27;self&\#x27; as required\. For older clients, also use X\-Frame\-Options: DENY or SAMEORIGIN\.

**References:**

- [Reference 1](https://owasp.org/www-project-secure-headers/)

### FINDING-014: X\-Content\-Type\-Options missing or ineffective

**Rule:** headers\.nosniff  
**Severity:** Low | **Confidence:** observation  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

MIME\-sniffing protection was absent or invalid; exploitation depends on served content and browser behavior\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Expected a single nosniff value.
```

**Remediation:**

Set X\-Content\-Type\-Options: nosniff and correct Content\-Type values at the app or proxy\.

**References:**

- [Reference 1](https://owasp.org/www-project-secure-headers/)

### FINDING-015: Unencoded benign metacharacters reflected in HTML

**Rule:** input\.html\_reflection  
**Severity:** Low | **Confidence:** needs-manual-verification  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

The exact inert marker and quote/angle/ampersand characters appeared in an HTML response\. This is a reflection signal, not proof of executable XSS; context, sanitizers and effective CSP require manual verification\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Existing query field inspected: q
An inert marker with unencoded metacharacters was reflected; no script or handler was sent/executed.
```

**Remediation:**

Apply context\-aware output encoding with framework autoescaping\. Avoid unsafe HTML sinks, sanitize intentional HTML with a maintained allowlist sanitizer, and enforce a tested CSP\. Review the actual output context in an owned test environment\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)
- [Reference 2](https://owasp.org/www-community/attacks/xss/)

### FINDING-016: HTTP response does not advertise an HTTPS upgrade

**Rule:** tls\.http\_upgrade  
**Severity:** Low | **Confidence:** observation  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

The approved HTTP endpoint responded without a Location redirect to HTTPS\. Whether plaintext access is intentional for an isolated lab or exposes sensitive data needs review; no credentials or response body were collected\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
HTTP response lacked a single HTTPS redirect destination.
Response body was not read and redirects were not followed.
```

**Remediation:**

On public deployments, redirect HTTP to HTTPS at the reverse proxy and use valid TLS\. Add HSTS on the HTTPS origin after verifying coverage\. Document any isolated HTTP\-only lab exception\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security)

### FINDING-017: Technology\-identifying headers are exposed

**Rule:** disclosure\.tech\_headers  
**Severity:** Info | **Confidence:** observation  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

Technology\-identifying headers were present\. Values may be generic, falsified or rewritten and are not evidence of an installed vulnerable version\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Present header names: server
Header values were omitted.
```

**Remediation:**

Remove unnecessary X\-Powered\-By/framework version headers and minimize proxy/server tokens\. Patch software independently of banner hiding\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage)

### FINDING-018: Administrative route responded

**Rule:** files\.admin\_route  
**Severity:** Info | **Confidence:** observation  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

The curated administrative path returned success metadata\. An accessible login page is normal; no authentication bypass or unauthorized administrative action was tested\.

**Evidence:**

```text
HEAD http://127.0.0.1:45301/admin/
HTTP status: 200
HEAD /admin/ returned 200; body and authentication state were not inspected.
```

**Remediation:**

Review the administrative surface, require strong authentication/MFA and authorization, and limit network access where appropriate\. Do not treat URL obscurity as access control\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information)

### FINDING-019: robots\.txt publishes URL inventory

**Rule:** files\.public\_inventory  
**Severity:** Info | **Confidence:** observation  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

The public metadata contains path references\. robots\.txt and sitemaps are discoverability controls, not access control\. Paths were inventoried without visiting them or claiming they are vulnerabilities\.

**Evidence:**

```text
GET http://127.0.0.1:45301/robots.txt
HTTP status: 200
Bounded references observed: 1; approved-scope references: 1.
Referenced paths/query values were not retained or fetched.
```

**Remediation:**

Exclude private URLs from public sitemaps and apply authentication/authorization to private paths\. Never rely on robots disallows to protect sensitive content\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage)

### FINDING-020: Potentially sensitive HTTP methods are advertised

**Rule:** headers\.methods  
**Severity:** Info | **Confidence:** observation  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

The response advertises methods that require deliberate authorization\. Advertisement does not prove the server accepts them or permits unauthenticated modification; no modifying request was sent\.

**Evidence:**

```text
OPTIONS http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Advertised methods: DELETE, PUT, TRACE
No PUT, DELETE or TRACE request was sent.
```

**Remediation:**

Disable TRACE and unused verbs at the proxy; require authorization and CSRF controls for legitimate write endpoints\. Verify allowed methods in an owned test environment\.

**References:**

- [Reference 1](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods)

### FINDING-021: Permissions\-Policy is absent

**Rule:** headers\.permissions  
**Severity:** Info | **Confidence:** observation  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

No explicit browser\-feature policy was observed\. This is optional hardening; browser defaults still apply\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Permissions-Policy header was absent.
```

**Remediation:**

Set only needed feature restrictions, for example Permissions\-Policy: camera=\(\), microphone=\(\), geolocation=\(\), after reviewing app requirements\.

**References:**

- [Reference 1](https://owasp.org/www-project-secure-headers/)

### FINDING-022: Explicit Referrer\-Policy is absent

**Rule:** headers\.referrer  
**Severity:** Info | **Confidence:** observation  
**CVSS v3.1:** Not scored — impact needs verification

**Description:**

No explicit policy was observed\. Modern browser defaults offer protection; this is a hardening observation rather than proof of referrer leakage\.

**Evidence:**

```text
GET http://127.0.0.1:45301/search?q=%5Bredacted%5D&id=%5Bredacted%5D&next=%5Bredacted%5D&file=%5Bredacted%5D
HTTP status: 200
Referrer-Policy header was absent.
```

**Remediation:**

Set Referrer\-Policy: strict\-origin\-when\-cross\-origin, or no\-referrer where required by privacy policy\.

**References:**

- [Reference 1](https://owasp.org/www-project-secure-headers/)

## Recommended next steps

1. Prioritize confirmed high-impact findings and verify potential issues before remediation decisions.
2. Resolve skipped, inconclusive and failed checks; rerun within the same authorized scope.
3. Retest fixes and supplement automated checks with manual application assessment.

Reports contain assessment metadata. Review and redact before publishing or sending to an issue tracker.
