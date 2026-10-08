"""Minimal disclosure signals: headers, HTML comments, verbose errors and map metadata."""

import re
from secrets import token_hex
from urllib.parse import urlsplit, urlunsplit

from scanner.checks.base import CheckContext, CheckInfo, register_check
from scanner.checks.web.common import (
    WSTG_ROOT,
    PageMetadata,
    WebCheck,
    WebRecord,
    approved_link,
    is_html,
    origin_url,
)
from scanner.checks.web.files import metadata_candidate, missing_control
from scanner.core.finding import Confidence, Severity
from scanner.core.session import HTTPResponse
from scanner.core.target import ScanMode

MAX_SCRIPTS = 4
MAX_COMMENT_SIGNALS = 3
COMMENT_SIGNALS = {
    "secret-assignment-like text": re.compile(r"\b(?:password|passwd|api[_-]?key|secret|token)\b\s*[:=]\s*\S+", re.I),
    "internal-address-like text": re.compile(
        r"(?:https?://(?:localhost|127\.0\.0\.1|10\.[0-9.]+|192\.168\.[0-9.]+)|\b(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b)",
        re.I,
    ),
    "private-key marker": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
ERROR_SIGNALS = {
    "Python traceback": re.compile(r"Traceback \(most recent call last\):[\s\S]{0,3000}File [\"']", re.I),
    "ASP.NET diagnostic page": re.compile(
        r"Server Error in ['\"]/[^'\"]*['\"] Application|\bSystem\.[A-Za-z]+Exception\b.*(?:at |stack)", re.I
    ),
    "Java stack trace": re.compile(
        r"\b(?:java|javax)\.[A-Za-z0-9_.]+Exception[\s\S]{0,1000}\bat [A-Za-z0-9_.$]+\([A-Za-z0-9_.]+\.java:[0-9]+\)"
    ),
    "PHP error with file/line": re.compile(
        r"(?:Fatal error|Warning):[\s\S]{0,1000}\bin [^\r\n<>]+ on line [0-9]+", re.I
    ),
    "Node stack trace": re.compile(
        r"(?:TypeError|ReferenceError|Error):[^\r\n]{0,200}[\s\S]{0,1000}\bat [^\r\n]{0,200}\([^\r\n]+:[0-9]+:[0-9]+\)"
    ),
}
SOURCE_MAP = re.compile(r"(?:[/][/*][#@]\s*sourceMappingURL\s*=\s*)([^\s*]{1,4096})")
DISCLOSURE_REFERENCE = WSTG_ROOT + "01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"


@register_check(
    CheckInfo(
        "disclosure",
        ScanMode.WEB,
        "Technology header presence, sensitive-comment categories, verbose error signatures and source-map HEAD metadata",
        72,
    )
)
class DisclosureCheck(WebCheck):
    """Observe disclosure without persisting headers, comments, source code or map bodies."""

    def inspect(self, context: CheckContext, record: WebRecord) -> None:
        """Read bounded public-page/script metadata and never download a source map."""
        response = context.http.request(context.target.url)
        present = tuple(
            name
            for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
            if response.header_values(name)
        )
        if present:
            record.add(
                "disclosure.tech_headers",
                "Technology-identifying headers are exposed",
                Severity.INFO,
                "Technology-identifying headers were present. Values may be generic, falsified or rewritten and are not evidence of an installed vulnerable version.",
                response,
                ("Present header names: " + ", ".join(present), "Header values were omitted."),
                "Remove unnecessary X-Powered-By/framework version headers and minimize proxy/server tokens. Patch software independently of banner hiding.",
                (DISCLOSURE_REFERENCE,),
            )
        self._errors(response, record)
        scripts: list[str] = []
        if is_html(response):
            metadata = PageMetadata()
            metadata.feed(response.text())
            if metadata.generator:
                record.add(
                    "disclosure.generator",
                    "HTML generator metadata is present",
                    Severity.INFO,
                    "A generator meta element identifies implementation metadata. Its contents were not retained or used to assert a software version.",
                    response,
                    ("A generator meta element was observed.",),
                    "Remove unnecessary generator metadata; keep exposed software and dependencies patched.",
                    (DISCLOSURE_REFERENCE,),
                )
            for category, pattern in COMMENT_SIGNALS.items():
                if any(pattern.search(comment) for comment in metadata.comments):
                    record.add(
                        "disclosure.comment",
                        "HTML comment contains a sensitive-information signal",
                        Severity.LOW,
                        "A bounded comment matched a sensitive-information category. It may be a dummy value or documentation; [Needs manual verification]. Comment content and potential secrets were not retained.",
                        response,
                        ("Matched category: " + category, "Comment text and values were omitted."),
                        "Remove secrets/internal deployment details from served HTML, including comments. Have the owner verify the signal and rotate any confirmed exposed credentials.",
                        (DISCLOSURE_REFERENCE,),
                        Confidence.POTENTIAL,
                    )
            scripts = metadata.scripts[:MAX_SCRIPTS]
            if len(metadata.scripts) > MAX_SCRIPTS:
                record.limit("Only the first four in-scope script candidates were inspected.")
        error_page = context.http.request(origin_url(context, "/vulnscan-not-present-" + token_hex(8)))
        self._errors(error_page, record)
        seen: set[str] = set()
        for value in scripts:
            script_url = approved_link(context, response.url, value)
            if script_url is None or not urlsplit(script_url).path.endswith((".js", ".mjs")):
                record.limit("A referenced script was outside scope or not a supported JavaScript path.")
                continue
            script = context.http.request(script_url)
            urls: list[str] = []
            for header_name in ("sourcemap", "x-sourcemap"):
                for header_value in script.header_values(header_name):
                    link = approved_link(context, script.url, header_value)
                    if link and urlsplit(link).path.endswith(".map"):
                        urls.append(link)
            for match in SOURCE_MAP.finditer(script.text()):
                link = approved_link(context, script.url, match.group(1))
                if link:
                    urls.append(link)
                    break
            parsed = urlsplit(script.url)
            if parsed.path.endswith(".js"):
                urls.append(urlunsplit((parsed.scheme, parsed.netloc, parsed.path + ".map", "", "")))
            for url in urls[:2]:
                if url in seen:
                    continue
                seen.add(url)
                path = urlsplit(url).path
                control = context.http.request(
                    origin_url(context, missing_control(path)), method="HEAD", read_body=False
                )
                candidate = context.http.request(url, method="HEAD", read_body=False)
                if metadata_candidate(candidate, control):
                    record.add(
                        "disclosure.source_map",
                        "Source-map URL returned distinct success metadata",
                        Severity.LOW,
                        "A referenced or conventional source-map URL returned non-HTML success distinct from a not-found control. Map contents, embedded source and private data were not downloaded; [Needs manual verification].",
                        candidate,
                        (
                            "HEAD map candidate succeeded while its randomized control was not found.",
                            "No source-map body or embedded source code was retrieved.",
                        ),
                        "Omit public source maps containing private source/configuration from production builds, or serve them only to an authenticated debugging service. Public maps with intentionally public source may be acceptable.",
                        (DISCLOSURE_REFERENCE,),
                        Confidence.POTENTIAL,
                        "HEAD",
                    )
                elif control.status_code == 200 or candidate.status_code in {405, 501}:
                    record.limit("Source-map HEAD metadata was ambiguous or unsupported.")

    def _errors(self, response: HTTPResponse, record: WebRecord) -> None:
        text = response.text()
        matched = tuple(name for name, pattern in ERROR_SIGNALS.items() if pattern.search(text))
        if matched:
            record.add(
                "disclosure.verbose_error",
                "Verbose error/stack-trace signature observed",
                Severity.LOW,
                "A response matched a framework diagnostic signature. The detector does not retain stack traces, source paths or values; the page may be documentation and needs contextual review.",
                response,
                (
                    "Matched diagnostic families: " + ", ".join(matched),
                    "Response snippets, source paths and values were omitted.",
                ),
                "Disable framework debug/stack-trace responses in production. Return generic error IDs and store detailed traces only in protected server logs. Review confirmed exposed details for secrets.",
                (WSTG_ROOT + "08-Testing_for_Error_Handling/01-Testing_for_Improper_Error_Handling",),
                Confidence.POTENTIAL,
            )
