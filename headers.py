"""Security header configuration and advertised methods; never send destructive verbs."""

import re
from ipaddress import ip_address

from scanner.checks.base import CheckContext, CheckInfo, register_check
from scanner.checks.web.common import WSTG_ROOT, WebCheck, WebRecord, is_html, is_success
from scanner.core.finding import Confidence, Severity
from scanner.core.target import ScanMode

HEADER_REFERENCE = "https://owasp.org/www-project-secure-headers/"
DANGEROUS_METHODS = frozenset({"PUT", "DELETE", "TRACE"})
STRICT_FRAME_SOURCES = re.compile(r"(?:https?://)?(?:\*\.)?[A-Za-z0-9.-]+(?::[0-9]+)?/?\Z")


def csp_directives(policy: str) -> dict[str, tuple[str, ...]]:
    """Parse structural directives using first occurrence, matching browser duplicate rules."""
    directives: dict[str, tuple[str, ...]] = {}
    for segment in policy.split(";"):
        tokens = segment.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tuple(tokens[1:]))
    return directives


def restrictive_ancestors(policies: tuple[str, ...]) -> bool:
    """A valid restrictive enforced policy can replace redundant X-Frame-Options."""
    for policy in policies:
        for part in policy.split(","):
            values = csp_directives(part).get("frame-ancestors", ())
            if values == ("'none'",):
                return True
            if values and all(
                value == "'self'" or (value != "*" and STRICT_FRAME_SOURCES.fullmatch(value)) for value in values
            ):
                return True
    return False


@register_check(
    CheckInfo("headers", ScanMode.WEB, "Security header presence/value checks and OPTIONS method advertisement", 16)
)
class HeadersCheck(WebCheck):
    """Detect defense gaps while avoiding browser-semantics and method-exploit overclaims."""

    def inspect(self, context: CheckContext, record: WebRecord) -> None:
        """Inspect representative headers, then OPTIONS without PUT/DELETE/TRACE requests."""
        response = context.http.request(context.target.url, read_body=False)
        references = (HEADER_REFERENCE,)
        if context.target.origin[0] == "https":
            try:
                ip_address(context.target.hostname)
                numeric = True
            except ValueError:
                numeric = False
            if not numeric:
                hsts = response.header_values("strict-transport-security")
                match = (
                    re.search(r'(?:^|;)\s*max-age\s*=\s*("[0-9]{1,12}"|[0-9]{1,12})\s*(?:;|$)', hsts[0], re.I)
                    if hsts
                    else None
                )
                # RFC 6797 section 8.1 uses the first field when multiple are sent.
                if len(hsts) > 1:
                    record.limit(
                        "Duplicate HSTS fields were observed; the first was assessed, but proxy configuration needs review."
                    )
                if not match or int(match.group(1).strip('"')) == 0:
                    record.add(
                        "headers.hsts",
                        "HSTS missing or inactive on HTTPS",
                        Severity.LOW,
                        "The observed HTTPS response does not establish an active HSTS policy. First-visit transport risk and deployment intent need manual verification.",
                        response,
                        ("No single positive max-age directive was observed.",),
                        "At the HTTPS reverse proxy, set Strict-Transport-Security: max-age=31536000 after verifying HTTPS coverage. Add includeSubDomains/preload only after checking every subdomain.",
                        references,
                    )
        if is_success(response):
            if response.header("x-content-type-options").strip().lower() != "nosniff":
                record.add(
                    "headers.nosniff",
                    "X-Content-Type-Options missing or ineffective",
                    Severity.LOW,
                    "MIME-sniffing protection was absent or invalid; exploitation depends on served content and browser behavior.",
                    response,
                    ("Expected a single nosniff value.",),
                    "Set X-Content-Type-Options: nosniff and correct Content-Type values at the app or proxy.",
                    references,
                )
            if not response.header_values("referrer-policy"):
                record.add(
                    "headers.referrer",
                    "Explicit Referrer-Policy is absent",
                    Severity.INFO,
                    "No explicit policy was observed. Modern browser defaults offer protection; this is a hardening observation rather than proof of referrer leakage.",
                    response,
                    ("Referrer-Policy header was absent.",),
                    "Set Referrer-Policy: strict-origin-when-cross-origin, or no-referrer where required by privacy policy.",
                    references,
                )
            elif response.header("referrer-policy").strip().lower().split(",")[-1].strip() == "unsafe-url":
                record.add(
                    "headers.referrer_unsafe",
                    "Referrer-Policy permits full-URL referrers",
                    Severity.LOW,
                    "The observed unsafe-url policy can expose path/query details in referrers; verify whether URLs contain sensitive information.",
                    response,
                    ("unsafe-url was the final advertised referrer policy.",),
                    "Replace unsafe-url with strict-origin-when-cross-origin or no-referrer and avoid secrets in URLs.",
                    references,
                )
            if is_html(response):
                policies = response.header_values("content-security-policy")
                if not policies:
                    observation = "No enforcing Content-Security-Policy header was observed."
                    if response.header_values("content-security-policy-report-only"):
                        observation += " Report-only does not enforce restrictions."
                    record.add(
                        "headers.csp",
                        "Enforcing Content Security Policy is absent",
                        Severity.LOW,
                        "This HTML response lacks a header-enforced CSP. CSP is defense in depth; absent CSP alone does not establish XSS. A meta-delivered policy has not been inspected by this header-only rule.",
                        response,
                        (observation,),
                        "Deploy a tested CSP with nonce/hash-based script sources, object-src 'none', base-uri 'self', and frame-ancestors 'none' or a justified allowlist. Use report-only during rollout, then enforce.",
                        references,
                    )
                else:
                    for policy in policies:
                        directives = csp_directives(policy)
                        scripts = directives.get("script-src", directives.get("default-src", ()))
                        nonce_or_hash = any(
                            value.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for value in scripts
                        )
                        if "'unsafe-eval'" in scripts or ("'unsafe-inline'" in scripts and not nonce_or_hash):
                            record.add(
                                "headers.csp_unsafe",
                                "CSP advertises permissive script directives",
                                Severity.LOW,
                                "A script policy contains unsafe-eval or unqualified unsafe-inline. Other simultaneous CSP policies may restrict the effective intersection; [Needs manual verification].",
                                response,
                                (
                                    "An enforced header advertises an unsafe script directive; policy text was not retained.",
                                ),
                                "Remove unsafe-eval and replace inline scripts with nonces or hashes. Evaluate all enforcing policies and test the effective browser policy.",
                                references,
                                Confidence.POTENTIAL,
                            )
                            break
                frame = response.header_values("x-frame-options")
                valid_xfo = len(frame) == 1 and frame[0].strip().upper() in {"DENY", "SAMEORIGIN"}
                if not valid_xfo and not restrictive_ancestors(policies):
                    record.add(
                        "headers.framing",
                        "No restrictive framing header was observed",
                        Severity.LOW,
                        "Neither a valid X-Frame-Options policy nor a structurally restrictive CSP frame-ancestors directive was observed. Actual clickjacking impact needs manual verification.",
                        response,
                        ("No supported restrictive framing control was found in response headers.",),
                        "Set CSP frame-ancestors 'none' or 'self' as required. For older clients, also use X-Frame-Options: DENY or SAMEORIGIN.",
                        references,
                    )
                if not response.header_values("permissions-policy"):
                    record.add(
                        "headers.permissions",
                        "Permissions-Policy is absent",
                        Severity.INFO,
                        "No explicit browser-feature policy was observed. This is optional hardening; browser defaults still apply.",
                        response,
                        ("Permissions-Policy header was absent.",),
                        "Set only needed feature restrictions, for example Permissions-Policy: camera=(), microphone=(), geolocation=(), after reviewing app requirements.",
                        references,
                    )
        else:
            record.limit("The initial response was not successful; representative page-header coverage is incomplete.")
        options = context.http.request(context.target.url, method="OPTIONS", read_body=False)
        methods = {
            token.strip().upper()
            for value in options.header_values("allow") + options.header_values("access-control-allow-methods")
            for token in value.split(",")
        }
        advertised = sorted(methods & DANGEROUS_METHODS)
        if advertised:
            record.add(
                "headers.methods",
                "Potentially sensitive HTTP methods are advertised",
                Severity.INFO,
                "The response advertises methods that require deliberate authorization. Advertisement does not prove the server accepts them or permits unauthenticated modification; no modifying request was sent.",
                options,
                ("Advertised methods: " + ", ".join(advertised), "No PUT, DELETE or TRACE request was sent."),
                "Disable TRACE and unused verbs at the proxy; require authorization and CSRF controls for legitimate write endpoints. Verify allowed methods in an owned test environment.",
                (WSTG_ROOT + "02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",),
                method="OPTIONS",
            )
        if options.status_code in {405, 501}:
            record.limit("OPTIONS was unsupported; method-advertisement coverage is incomplete.")
