"""Benign input signals, negative controls and authentication/state-changing exclusions."""

import html
import json

import pytest

from scanner.checks.web.redirect import RedirectCheck
from scanner.checks.web.sqli import SQLiCheck
from scanner.checks.web.traversal import TraversalCheck
from scanner.checks.web.xss import XSSCheck
from scanner.core.config import ConfigError, ScanConfig
from scanner.core.finding import Confidence
from scanner.core.result import CheckStatus
from scanner.safety.state import AuthorizationStore
from tests.web_lab import Reply, Request, serve_web_lab
from tests.web_support import web_context


@pytest.mark.parametrize("encoded", [True, False])
def test_html_reflection_without_script_payload(state: AuthorizationStore, encoded: bool) -> None:
    """Encoded HTML output is not XSS; literal metacharacters remain a potential signal."""
    with serve_web_lab() as lab:

        def reflected(request: Request) -> Reply:
            value = request.value("q")
            return Reply(body=("<p>" + (html.escape(value) if encoded else value) + "</p>").encode())

        lab.routes["/search"] = reflected
        report = XSSCheck().run(web_context(state, lab.url + "/search?q=public"))
        assert bool(report.findings) is not encoded
        assert report.status is CheckStatus.COMPLETE
        for request in lab.requests:
            assert "<script" not in request.value("q").lower() and "onerror" not in request.value("q").lower()
        if report.findings:
            assert report.findings[0].confidence is Confidence.POTENTIAL
            assert "not proof" in report.findings[0].description


def test_json_reflection_is_not_html_xss(state: AuthorizationStore) -> None:
    """A JSON string containing quotes/angles does not establish executable HTML."""
    with serve_web_lab() as lab:
        lab.routes["/search"] = lambda request: Reply(
            body=json.dumps({"q": request.value("q")}).encode(), headers=(("Content-Type", "application/json"),)
        )
        report = XSSCheck().run(web_context(state, lab.url + "/search?q=public"))
        assert not report.findings and report.status is CheckStatus.SKIPPED


@pytest.mark.parametrize("baseline_error", [True, False])
def test_single_quote_parser_error_baseline(state: AuthorizationStore, baseline_error: bool) -> None:
    """Only new DB signatures are candidates; original errors are not attributed to a probe."""
    with serve_web_lab() as lab:

        def sql_route(request: Request) -> Reply:
            body = (
                b"You have an error in your SQL syntax; synthetic-private-query"
                if baseline_error or request.value("id") == "1'"
                else b"ordinary page"
            )
            return Reply(body=body)

        lab.routes["/search"] = sql_route
        report = SQLiCheck().run(web_context(state, lab.url + "/search?id=1"))
        assert bool(report.findings) is not baseline_error
        assert [request.value("id") for request in lab.requests] == ["1", "1'"]
        assert "synthetic-private-query" not in str([item.to_dict() for item in report.findings])


@pytest.mark.parametrize(
    "suffix",
    [
        "/login?id=1",
        "/login.php?id=1",
        "/delete?id=1",
        "/search?username=public",
        "/search?token=synthetic-secret",
        "/search?action=delete",
        "/search",
    ],
)
def test_active_authentication_or_stateful_inputs_skip_before_io(state: AuthorizationStore, suffix: str) -> None:
    """Never append a quote or marker to authentication/action fields or routes."""
    with serve_web_lab() as lab:
        for rule in (XSSCheck(), SQLiCheck(), RedirectCheck()):
            report = rule.run(web_context(state, lab.url + suffix))
            assert report.status is CheckStatus.SKIPPED and not report.findings
        assert not lab.requests


@pytest.mark.parametrize("allow_external", [True, False])
def test_external_location_control_without_following(state: AuthorizationStore, allow_external: bool) -> None:
    """Only a random marker becoming the effective external hostname establishes behavior."""
    with serve_web_lab() as lab:

        def redirect(request: Request) -> Reply:
            supplied = request.value("next")
            location = supplied if allow_external else "/safe?next=" + supplied
            return Reply(302, headers=(("Location", location),))

        lab.routes["/leave"] = redirect
        report = RedirectCheck().run(web_context(state, lab.url + "/leave?next=%2Fsafe"))
        assert bool(report.findings) is allow_external
        assert len(lab.requests) == 2 and all(request.path == "/leave" for request in lab.requests)
        if report.findings:
            assert report.findings[0].confidence is Confidence.CONFIRMED
            assert report.findings[0].cvss is None
            assert all(".invalid" not in item.path for item in lab.requests)


def test_probe_parameter_cap_and_duplicate_key_order(state: AuthorizationStore) -> None:
    """Only four fields are probed and mutating one duplicate does not rewrite its siblings."""
    with serve_web_lab() as lab:
        lab.routes["/search"] = Reply()
        report = SQLiCheck().run(web_context(state, lab.url + "/search?q=one&q=two&a=1&b=2&c=3"))
        assert report.status is CheckStatus.INCONCLUSIVE and len(lab.requests) == 5
        assert lab.requests[1].query[:2] == (("q", "one'"), ("q", "two"))
        assert lab.requests[2].query[:2] == (("q", "one"), ("q", "two'"))


def test_traversal_requires_explicit_canary_and_real_differential(state: AuthorizationStore) -> None:
    """Only public fixture content is used; missing/basename controls must differ."""
    with serve_web_lab() as lab:
        skipped = TraversalCheck().run(web_context(state, lab.url + "/download?file=public.txt"))
        assert skipped.status is CheckStatus.SKIPPED and not lab.requests
        path = "/vulnscanner-canary-" + "a" * 32 + ".txt"
        token = "vulnscanner-canary-" + "b" * 32
        basename = path.lstrip("/")
        lab.routes[path] = Reply(body=token.encode(), headers=(("Content-Type", "text/plain"),))

        def download(request: Request) -> Reply:
            return Reply(body=token.encode() if request.value("file") == "../" + basename else b"no canary")

        lab.routes["/download"] = download
        config = ScanConfig(traversal_canary_path=path, traversal_canary_token=token)
        report = TraversalCheck().run(web_context(state, lab.url + "/download?file=public.txt", config))
        assert len(report.findings) == 1 and report.findings[0].confidence is Confidence.POTENTIAL
        assert all("/etc" not in request.path and "passwd" not in str(request.query) for request in lab.requests)
        assert token not in str(report.findings[0].to_dict())
        lab.routes["/download"] = Reply(body=token.encode())
        assert not TraversalCheck().run(web_context(state, lab.url + "/download?file=public.txt", config)).findings


@pytest.mark.parametrize(
    "settings",
    [
        {"traversal_canary_path": "/etc/passwd", "traversal_canary_token": "unsafe"},
        {"traversal_canary_path": "/vulnscanner-canary-aaaaaaaaaaaaaaaa.txt"},
        {"weak_tls_probes": "yes"},
        {"tls_expiry_days": 0},
    ],
)
def test_new_security_config_rejects_invalid_probes(settings: dict[str, object]) -> None:
    """A private file path cannot be substituted for the named public canary contract."""
    with pytest.raises(ConfigError):
        ScanConfig(**settings)
