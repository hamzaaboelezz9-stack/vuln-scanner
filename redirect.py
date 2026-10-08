"""Verify externally controlled redirect headers without contacting their destination."""

from secrets import token_hex
from urllib.parse import urljoin, urlsplit

from scanner.checks.base import CheckContext, CheckInfo, register_check
from scanner.checks.web.common import WSTG_ROOT, WebCheck, WebRecord, input_parameters, mutate_query
from scanner.core.finding import Confidence, Severity
from scanner.core.session import REDIRECT_STATUSES
from scanner.core.target import ScanMode

REDIRECT_FIELDS = frozenset(
    {"url", "redirect", "next", "return", "returnurl", "redirect_uri", "redirect_url", "continue", "destination"}
)


@register_check(
    CheckInfo(
        "redirect", ScanMode.WEB, "Observe random external redirect destinations in Location without following them", 28
    )
)
class RedirectCheck(WebCheck):
    """Establish controlled Location behavior; no phishing page or external request is used."""

    def inspect(self, context: CheckContext, record: WebRecord) -> None:
        """Compare original redirects with a reserved-domain marker in existing fields."""
        parameters = input_parameters(context, record, REDIRECT_FIELDS)
        baseline = context.http.request(context.target.url, read_body=False)
        for index, name in parameters:
            destination = "https://vulnscan-" + token_hex(8) + ".invalid/"
            response = context.http.request(mutate_query(context.target.url, index, destination), read_body=False)
            locations = response.header_values("location")
            if len(locations) > 1:
                record.limit("Multiple Location headers could not establish a reliable redirect destination.")
                continue
            if response.status_code not in REDIRECT_STATUSES or len(locations) != 1:
                continue
            try:
                effective = urlsplit(urljoin(response.url, locations[0]))
                expected = urlsplit(destination)
            except ValueError:
                record.limit("A malformed Location header could not be analyzed.")
                continue
            if (
                effective.scheme in {"http", "https"}
                and effective.hostname == expected.hostname
                and destination not in baseline.header("location")
            ):
                record.add(
                    "input.open_redirect",
                    "Query parameter controls an external HTTP redirect",
                    Severity.MEDIUM,
                    "A unique reserved-domain marker supplied in an existing query field became the external Location destination of a redirect response. This establishes externally controlled redirect behavior; business impact and intentional redirect policy need review. The destination was never resolved or contacted.",
                    response,
                    (
                        "Existing query field inspected: " + name,
                        "A unique reserved-domain marker became the redirect hostname.",
                        "Redirect following was disabled; no external service was contacted.",
                    ),
                    "Allow only approved relative paths or exact trusted origins. Parse and compare canonical scheme/host/port rather than substrings; reject scheme-relative destinations and credentials. For intentional external links, use a clear interstitial and avoid sensitive tokens in URLs.",
                    (
                        WSTG_ROOT + "11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
                        "https://cwe.mitre.org/data/definitions/601.html",
                    ),
                    Confidence.CONFIRMED,
                )
