"""CORS header behavior using inert Origin strings; no cross-origin request is followed."""

from secrets import token_hex

from scanner.checks.base import CheckContext, CheckInfo, register_check
from scanner.checks.web.common import WSTG_ROOT, WebCheck, WebRecord
from scanner.core.finding import Confidence, Severity
from scanner.core.session import HTTPResponse
from scanner.core.target import ScanMode

CORS_REFERENCE = WSTG_ROOT + "11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"
ORIGIN_REFERENCE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin"


def credentials_enabled(response: HTTPResponse) -> bool:
    """Browsers require exactly one case-sensitive 'true' credential value."""
    return response.header_values("access-control-allow-credentials") == ("true",)


@register_check(
    CheckInfo(
        "cors", ScanMode.WEB, "Reflected/null Origin and wildcard/credential configuration, plus GET preflight", 24
    )
)
class CorsCheck(WebCheck):
    """Distinguish arbitrary credentialed origins from invalid browser-blocked wildcard CORS."""

    def inspect(self, context: CheckContext, record: WebRecord) -> None:
        """Probe two random reserved origins, null and an OPTIONS preflight without cookies."""
        origins = tuple(f"https://vulnscan-{token_hex(8)}.invalid" for _ in range(2))
        replies = [
            context.http.request(context.target.url, headers={"Origin": origin}, read_body=False) for origin in origins
        ]
        references = (CORS_REFERENCE, ORIGIN_REFERENCE)
        for response in replies:
            values = response.header_values("access-control-allow-origin")
            if len(values) > 1:
                record.limit(
                    "Multiple Access-Control-Allow-Origin lines are invalid in browsers; manual configuration review is required."
                )
            if values == ("*",) and credentials_enabled(response):
                record.add(
                    "cors.wildcard_credentials",
                    "Invalid wildcard CORS with credentials",
                    Severity.LOW,
                    "The response combines wildcard origin with credential allowance. Browsers block credentialed reads in this configuration; this finding does not claim credential theft.",
                    response,
                    (
                        "Access-Control-Allow-Origin was wildcard and credential allowance was true.",
                        "No credentials or cookies were sent.",
                    ),
                    "Use explicit trusted origin matching when credentials are required; otherwise disable credential allowance for public wildcard resources.",
                    references,
                    Confidence.CONFIRMED,
                )
                break
        reflected = all(
            response.header_values("access-control-allow-origin") == (origin,)
            for origin, response in zip(origins, replies)
        )
        if reflected:
            credentialed = all(credentials_enabled(response) for response in replies)
            record.add(
                "cors.reflected_origin",
                "Arbitrary Origin reflection observed",
                Severity.MEDIUM if credentialed else Severity.INFO,
                "Two independent reserved origins were echoed. Credentialed private-data impact depends on authenticated endpoints, cookies and browser behavior; [Needs manual verification]. Uncredentialed public endpoints may intentionally allow this.",
                replies[0],
                (
                    "Two random Origin values were echoed exactly.",
                    "Credential allowance: " + ("true" if credentialed else "not consistently enabled"),
                    "No cross-origin destination was contacted and no credentials were sent.",
                ),
                "Match serialized origins against an exact trusted allowlist. Reject unknown/null origins for private resources, enable credentials only where needed, and include Vary: Origin on dynamically selected origins.",
                references,
                Confidence.POTENTIAL if credentialed else Confidence.OBSERVATION,
            )
            if any(
                not ({"origin", "*"} & {token.strip().lower() for token in response.header("vary").split(",")})
                for response in replies
            ):
                record.add(
                    "cors.vary",
                    "Dynamic CORS origin lacks Vary: Origin",
                    Severity.LOW,
                    "A reflected-origin response did not advertise Origin variation. Actual cache confusion depends on response cacheability and infrastructure.",
                    replies[0],
                    ("Dynamic origin selection observed without consistent Vary: Origin.",),
                    "Add Vary: Origin to dynamic CORS responses and review intermediary cache keys and private-response caching.",
                    references,
                )
        null = context.http.request(context.target.url, headers={"Origin": "null"}, read_body=False)
        if null.header_values("access-control-allow-origin") == ("null",) and credentials_enabled(null):
            record.add(
                "cors.null_origin",
                "Credentialed null Origin is accepted",
                Severity.MEDIUM,
                "Sandboxed/non-hierarchical origins can serialize to null. Sensitive credentialed impact remains unverified because no authenticated request was made.",
                null,
                ("Origin null was accepted with credential allowance true.",),
                "Reject null origins on private resources; use an explicit trusted origin allowlist and justify any public null-origin access.",
                references,
                Confidence.POTENTIAL,
            )
        preflight = context.http.request(
            context.target.url,
            method="OPTIONS",
            headers={"Origin": origins[0], "Access-Control-Request-Method": "GET"},
            read_body=False,
        )
        if preflight.status_code in {405, 501}:
            record.limit("GET preflight was unsupported; preflight behavior was not fully inspected.")
