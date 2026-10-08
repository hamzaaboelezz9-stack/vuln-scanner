"""Benign metacharacter reflection; no script, event handler or browser execution."""

from secrets import token_hex

from scanner.checks.base import CheckContext, CheckInfo, register_check
from scanner.checks.web.common import WSTG_ROOT, WebCheck, WebRecord, input_parameters, is_html, mutate_query
from scanner.core.finding import Confidence, Severity
from scanner.core.target import ScanMode
from scanner.utils.wordlists import load_wordlist


@register_check(
    CheckInfo(
        "xss", ScanMode.WEB, "Inert marker reflection on existing safe query fields; never claim executed XSS", 28
    )
)
class XSSCheck(WebCheck):
    """Observe unsafe-looking HTML reflection; contextual exploitability remains unverified."""

    def inspect(self, context: CheckContext, record: WebRecord) -> None:
        """Compare literal benign metacharacters with an unmodified HTML response."""
        parameters = input_parameters(context, record)
        baseline = context.http.request(context.target.url)
        if not is_html(baseline):
            record.skipped = True
            record.limit("The endpoint did not return HTML; HTML-reflection detection was not applicable.")
            return
        templates = load_wordlist("xss_payloads.txt")
        if templates != ("{marker}_\"'<> &",):
            raise ValueError("Only the fixed inert reflection template is permitted.")
        for index, name in parameters:
            marker = "vulnscan_" + token_hex(8)
            payload = templates[0].replace("{marker}", marker)
            response = context.http.request(mutate_query(context.target.url, index, payload))
            if is_html(response) and payload in response.text() and marker not in baseline.text():
                record.add(
                    "input.html_reflection",
                    "Unencoded benign metacharacters reflected in HTML",
                    Severity.LOW,
                    "The exact inert marker and quote/angle/ampersand characters appeared in an HTML response. This is a reflection signal, not proof of executable XSS; context, sanitizers and effective CSP require manual verification.",
                    response,
                    (
                        "Existing query field inspected: " + name,
                        "An inert marker with unencoded metacharacters was reflected; no script or handler was sent/executed.",
                    ),
                    "Apply context-aware output encoding with framework autoescaping. Avoid unsafe HTML sinks, sanitize intentional HTML with a maintained allowlist sanitizer, and enforce a tested CSP. Review the actual output context in an owned test environment.",
                    (
                        WSTG_ROOT + "07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
                        "https://owasp.org/www-community/attacks/xss/",
                    ),
                    Confidence.POTENTIAL,
                )
