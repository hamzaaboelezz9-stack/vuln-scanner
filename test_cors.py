"""Reserved Origin probes validate behavior without resolving/contacting the probe domain."""

import pytest

from scanner.checks.web.cors import CorsCheck
from scanner.core.finding import Confidence, Severity
from scanner.safety.state import AuthorizationStore
from tests.web_lab import Reply, Request, serve_web_lab
from tests.web_support import web_context


@pytest.mark.parametrize("credentials", ["true", "True", "false", ""])
def test_origin_reflection_credential_semantics(state: AuthorizationStore, credentials: str) -> None:
    """Only exact lowercase true is browser-compatible credential allowance."""
    with serve_web_lab() as lab:

        def reflected(request: Request) -> Reply:
            return Reply(
                headers=(
                    ("Access-Control-Allow-Origin", request.headers.get("Origin", "")),
                    ("Access-Control-Allow-Credentials", credentials),
                )
            )

        lab.routes["/"] = reflected
        report = CorsCheck().run(web_context(state, lab.url))
        reflection = next(item for item in report.findings if item.rule_id == "cors.reflected_origin")
        assert reflection.severity is (Severity.MEDIUM if credentials == "true" else Severity.INFO)
        assert reflection.confidence is (Confidence.POTENTIAL if credentials == "true" else Confidence.OBSERVATION)
        assert len(lab.requests) == 4 and {request.method for request in lab.requests} == {"GET", "OPTIONS"}
        assert all("Cookie" not in request.headers for request in lab.requests)


def test_wildcard_with_credentials_is_browser_blocked_config(state: AuthorizationStore) -> None:
    """Do not falsely describe wildcard credentials as a confirmed exfiltration vulnerability."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply(
            headers=(("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true"))
        )
        report = CorsCheck().run(web_context(state, lab.url))
        assert len(report.findings) == 1 and report.findings[0].rule_id == "cors.wildcard_credentials"
        assert "Browsers block" in report.findings[0].description


def test_public_wildcard_and_fixed_allowlist_are_not_vulnerabilities(state: AuthorizationStore) -> None:
    """Public uncredentialed resources and fixed trusted origins are normal configurations."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply(headers=(("Access-Control-Allow-Origin", "*"),))
        assert not CorsCheck().run(web_context(state, lab.url)).findings
        lab.routes["/"] = Reply(
            headers=(
                ("Access-Control-Allow-Origin", "https://trusted.example"),
                ("Access-Control-Allow-Credentials", "true"),
                ("Vary", "Origin"),
            )
        )
        assert not CorsCheck().run(web_context(state, lab.url)).findings


def test_vary_wildcard_is_not_reported_as_missing_origin(state: AuthorizationStore) -> None:
    """Vary wildcard prevents cache reuse and does not need an additional Origin token."""
    with serve_web_lab() as lab:
        lab.routes["/"] = lambda request: Reply(
            headers=(("Access-Control-Allow-Origin", request.headers.get("Origin", "")), ("Vary", "*"))
        )
        report = CorsCheck().run(web_context(state, lab.url))
        assert "cors.vary" not in {item.rule_id for item in report.findings}
