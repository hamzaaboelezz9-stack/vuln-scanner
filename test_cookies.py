"""Cookie values/names never appear in findings; flags and malformed inputs remain explicit."""

import pytest

from scanner.checks.web.cookies import CookiesCheck
from scanner.core.result import CheckStatus
from scanner.safety.state import AuthorizationStore
from tests.web_lab import Reply, serve_web_lab
from tests.web_support import web_context


def test_cookie_security_flags_and_secret_omission(state: AuthorizationStore) -> None:
    """Independent cookie lines are evaluated without disclosing their synthetic secrets."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply(
            headers=(
                ("Set-Cookie", "synthetic-private-name=synthetic-private-value; Path=/"),
                ("Set-Cookie", "safe=fixture; Secure; HttpOnly; SameSite=Strict"),
            )
        )
        report = CookiesCheck().run(web_context(state, lab.url))
        assert len(report.findings) == 1
        evidence = str(report.findings[0].to_dict())
        assert "synthetic-private" not in evidence and "Secure absent" in evidence
        assert "HttpOnly absent" in evidence and "SameSite absent" in evidence
        assert all("Cookie" not in request.headers for request in lab.requests)


@pytest.mark.parametrize(
    "header",
    [
        "token=fixture; HttpOnly; SameSite=None",
        "__Host-unique=fixture; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=fixture.local",
        "__Secure-unique=fixture; HttpOnly; SameSite=Lax",
    ],
)
def test_invalid_cookie_constraints(state: AuthorizationStore, header: str) -> None:
    """Invalid SameSite/prefix combinations are observations, never credential theft claims."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply(headers=(("Set-Cookie", header),))
        assert CookiesCheck().run(web_context(state, lab.url)).findings


@pytest.mark.parametrize(
    "header", ["not-a-cookie", 'a="semicolon; Secure"', "a=fixture; SameSite=Lax; SameSite=None; Secure; HttpOnly"]
)
def test_malformed_or_duplicate_cookie_is_incomplete(state: AuthorizationStore, header: str) -> None:
    """Malformed/ambiguous cookie syntax cannot be silently marked clean."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply(headers=(("Set-Cookie", header),))
        assert CookiesCheck().run(web_context(state, lab.url)).status is CheckStatus.INCONCLUSIVE


def test_cookie_cap_and_partitioned_flag(state: AuthorizationStore) -> None:
    """Handle modern extra attributes without relying on version-specific SimpleCookie tables."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply(
            headers=tuple(
                ("Set-Cookie", f"a{index}=fixture; Secure; HttpOnly; SameSite=None; Partitioned") for index in range(33)
            )
        )
        report = CookiesCheck().run(web_context(state, lab.url))
        assert not report.findings and report.status is CheckStatus.INCONCLUSIVE
