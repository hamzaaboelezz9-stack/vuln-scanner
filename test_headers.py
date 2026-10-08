"""Header semantics and OPTIONS advertisements tested with actual loopback responses."""

from pathlib import Path

import pytest

from scanner.checks.web.headers import HeadersCheck, csp_directives, restrictive_ancestors
from scanner.core.config import ScanConfig
from scanner.core.result import CheckStatus
from scanner.safety.state import AuthorizationStore
from tests.web_lab import Reply, Request, serve_web_lab
from tests.web_support import web_context

SECURE_HTML_HEADERS = (
    ("Content-Type", "text/html"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=()"),
)


def test_header_absence_and_non_destructive_methods(state: AuthorizationStore) -> None:
    """Capture missing defenses and advertisement without sending any advertised write verb."""
    with serve_web_lab() as lab:

        def root(request: Request) -> Reply:
            return Reply(headers=(("Content-Type", "text/html"), ("Allow", "GET, HEAD, PUT, DELETE, TRACE")))

        lab.routes["/"] = root
        report = HeadersCheck().run(web_context(state, lab.url))
        rules = {finding.rule_id for finding in report.findings}
        assert rules == {
            "headers.nosniff",
            "headers.referrer",
            "headers.csp",
            "headers.framing",
            "headers.permissions",
            "headers.methods",
        }
        assert {request.method for request in lab.requests} == {"GET", "OPTIONS"}
        assert report.status is CheckStatus.COMPLETE
        assert all(finding.cvss is None for finding in report.findings)


def test_csp_frame_ancestors_replaces_xfo_and_nonce_inline(state: AuthorizationStore) -> None:
    """Do not flag absent XFO when CSP protects framing or nonce-qualified unsafe-inline."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply(headers=SECURE_HTML_HEADERS)
        assert not HeadersCheck().run(web_context(state, lab.url)).findings
        lab.routes["/"] = Reply(
            headers=tuple(
                (
                    name,
                    "script-src 'nonce-abcdefghijklmnop' 'unsafe-inline'; frame-ancestors 'self'"
                    if name == "Content-Security-Policy"
                    else value,
                )
                for name, value in SECURE_HTML_HEADERS
            )
        )
        assert not HeadersCheck().run(web_context(state, lab.url)).findings


def test_report_only_and_json_applicability(state: AuthorizationStore) -> None:
    """Report-only does not count as enforcement; JSON does not need HTML framing policy."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply(
            headers=(("Content-Type", "text/html"), ("Content-Security-Policy-Report-Only", "default-src 'none'"))
        )
        assert any(item.rule_id == "headers.csp" for item in HeadersCheck().run(web_context(state, lab.url)).findings)
        lab.routes["/"] = Reply(
            body=b"{}",
            headers=(
                ("Content-Type", "application/json"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
            ),
        )
        assert not HeadersCheck().run(web_context(state, lab.url)).findings


@pytest.mark.parametrize(
    "policy,expected",
    [
        ("frame-ancestors 'none'", True),
        ("frame-ancestors 'self'", True),
        ("frame-ancestors https://trusted.example", True),
        ("frame-ancestors *", False),
        ("frame-ancestors https:", False),
        ("default-src 'none'", False),
        ("frame-ancestors invalid??", False),
    ],
)
def test_frame_ancestor_structure(policy: str, expected: bool) -> None:
    """Only supported restrictive frame-ancestors syntax can suppress a missing-XFO signal."""
    assert restrictive_ancestors((policy,)) is expected
    assert csp_directives("script-src 'self'; script-src *")["script-src"] == ("'self'",)


def test_hsts_inactive_and_valid_on_named_https(state: AuthorizationStore, tmp_path: Path) -> None:
    """Evaluate HSTS on a named HTTPS fixture while preserving full certificate verification."""
    with serve_web_lab(tmp_path) as lab:
        config = ScanConfig(ca_bundle=lab.ca_bundle)
        lab.routes["/"] = Reply(headers=SECURE_HTML_HEADERS + (("Strict-Transport-Security", "max-age=0"),))
        assert {item.rule_id for item in HeadersCheck().run(web_context(state, lab.url, config)).findings} == {
            "headers.hsts"
        }
        lab.routes["/"] = Reply(
            headers=SECURE_HTML_HEADERS + (("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),)
        )
        assert not HeadersCheck().run(web_context(state, lab.url, config)).findings


def test_duplicate_hsts_first_positive_and_quoted_age(state: AuthorizationStore, tmp_path: Path) -> None:
    """A valid first STS field is effective, while duplicate configuration stays visible."""
    with serve_web_lab(tmp_path) as lab:
        lab.routes["/"] = Reply(
            headers=(
                ("Content-Type", "text/html"),
                ("Strict-Transport-Security", 'max-age="31536000"'),
                ("Strict-Transport-Security", "max-age=0"),
            )
        )
        report = HeadersCheck().run(web_context(state, lab.url, ScanConfig(ca_bundle=lab.ca_bundle)))
        assert not any(item.rule_id == "headers.hsts" for item in report.findings)
        assert report.status.value == "inconclusive"
        assert "Duplicate HSTS" in report.reason
