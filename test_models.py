"""Known scoring vectors, redaction and explicit incomplete coverage."""

from datetime import datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from scanner.checks.base import BaseCheck, CheckContext, CheckInfo, CheckRegistry
from scanner.core.cvss import CVSS31
from scanner.core.finding import Confidence, Evidence, Finding, Severity
from scanner.core.result import CheckOutcome, CheckStatus, ScanResult
from scanner.core.target import ScanMode, Target


@pytest.mark.parametrize(
    ("metrics", "score"),
    [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N", 2.7),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_known_vectors(metrics: str, score: float) -> None:
    """Check published base-scoring equations against reproducible vectors."""
    assert CVSS31("CVSS:3.1/" + metrics).score == score


def test_invalid_cvss_and_evidence_redaction() -> None:
    """Reject incomplete vectors and remove secret-bearing request metadata."""
    with pytest.raises(ValueError):
        CVSS31("CVSS:3.1/AV:N/AV:N")
    evidence = Evidence(
        "GET", "http://localhost/login?token=secret", ("Set-Cookie: session=private", "password=hidden\x1b[31m")
    )
    finding = Finding(
        "headers.csp",
        "Missing CSP",
        Severity.LOW,
        Confidence.CONFIRMED,
        "CSP was absent on this response.",
        evidence,
        "Configure a restrictive policy.",
    )
    serialized = str(finding.to_dict())
    assert all(value not in serialized for value in ("secret", "private", "hidden", "\x1b"))
    assert finding.to_dict()["cvss"] is None


def test_incomplete_coverage_is_not_clean() -> None:
    """Zero findings still preserves failed checks and missing evidence."""
    result = ScanResult(uuid4(), Target.web("http://localhost"))
    result.outcomes.append(
        CheckOutcome("tls", CheckStatus.INCONCLUSIVE, "Local TLS backend cannot perform this probe.")
    )
    result.finish()
    assert result.to_dict()["coverage"][0]["status"] == "inconclusive"
    with pytest.raises(ValueError):
        CheckOutcome("tls", CheckStatus.FAILED)
    with pytest.raises(ValueError):
        result.finish(datetime(2000, 1, 1))


def test_registry_checks_are_concrete_and_mode_specific() -> None:
    """Registration imports metadata; only explicit execution runs a check."""
    registry = CheckRegistry()
    calls: list[str] = []
    info = CheckInfo("headers", ScanMode.WEB, "Inspect response headers.", 1)

    @registry.register(info)
    class LocalCheck(BaseCheck):
        """Test-only check with no network activity."""

        def run(self, context: CheckContext) -> list[Finding]:
            """Record invocation for the execution contract test."""
            calls.append(context.target.hostname)
            return []

    checks = registry.create(ScanMode.WEB)
    assert calls == [] and checks[0].info == info
    checks[0].run(SimpleNamespace(target=Target.web("http://localhost"), scan_id=uuid4()))
    assert calls == ["localhost"]
    with pytest.raises(ValueError):
        registry.register(info)(LocalCheck)
    with pytest.raises(ValueError):
        registry.create(ScanMode.NETWORK, ["headers"])
    with pytest.raises(ValueError):
        registry.create(ScanMode.WEB, ["missing"])
    with pytest.raises(TypeError):
        registry.register(CheckInfo("abstract", ScanMode.WEB, "Invalid.", 1))(BaseCheck)
