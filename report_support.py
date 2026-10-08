"""Fictional report-only fixtures; these are not measured target vulnerabilities."""

from datetime import datetime, timedelta, timezone
from uuid import UUID

from scanner.core.cvss import CVSS31
from scanner.core.finding import Confidence, Evidence, Finding, Severity
from scanner.core.result import CheckOutcome, CheckStatus, ScanResult
from scanner.core.target import Target
from scanner.reporting.model import ReportDocument


def report_result(text: str = "Literal fixture", scored: bool = False) -> ScanResult:
    """Construct a deterministic fictional finding for output security tests."""
    started = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
    finding = Finding(
        "fixture.example",
        text,
        Severity.MEDIUM,
        Confidence.POTENTIAL,
        text + "\nA fictional output test, not a vulnerability assertion.",
        Evidence(
            "GET", "http://localhost:3000/path?token=never-publish", (text, "Set-Cookie: private=never-publish"), 200
        ),
        text + "\nVerify target applicability before remediation.",
        ("https://owasp.org/www-project-top-ten/?token=never-publish#fragment",),
        CVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") if scored else None,
    )
    result = ScanResult(
        UUID("b0d8e8ca-79a1-4e93-825e-21f99c12a773"),
        Target.web("http://localhost:3000"),
        started,
        findings=[finding],
        outcomes=[CheckOutcome("headers", CheckStatus.COMPLETE)],
        operation_counts={"HTTP": 1, "TCP": 0, "TLS": 0},
        approved_addresses=("127.0.0.1",),
        approved_ports=(3000,),
    )
    result.finish(started + timedelta(seconds=1))
    return result


def report_document(text: str = "Literal fixture", scored: bool = False) -> ReportDocument:
    """Create a validated immutable document with explicit fictional provenance."""
    return ReportDocument.from_result(report_result(text, scored), purpose="Fictional report-only test fixture.")
