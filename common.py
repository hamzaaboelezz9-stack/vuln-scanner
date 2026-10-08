"""Shared network evidence helpers and explicit incomplete-survey handling."""

from scanner.checks.base import CheckContext, CheckReport
from scanner.checks.network.survey import SurveyResult
from scanner.core.finding import Confidence, Evidence, Finding, Severity
from scanner.core.network import PortObservation
from scanner.core.result import CheckStatus

MAX_NETWORK_FINDINGS = 256
NETWORK_REFERENCE = "https://nmap.org/book/port-scanning.html"


def survey_result(context: CheckContext) -> SurveyResult:
    """Require the engine-owned shared survey instead of opening duplicate connections."""
    if context.network is None:
        raise ValueError("Network checks require an engine-owned shared survey.")
    return context.network.collect(context)


def report(result: SurveyResult, findings: tuple[Finding, ...], notes: tuple[str, ...] = ()) -> CheckReport:
    """Preserve observations with missing coverage or unexpected worker errors."""
    reasons = list(notes)
    if result.incomplete:
        reasons.append("The host/port matrix was not completely observed; no unobserved pair is closed or safe.")
    if len(findings) > MAX_NETWORK_FINDINGS:
        reasons.append(
            "Finding output stopped at 256 records for this check; the surface summary retains aggregate counts."
        )
    status = CheckStatus.FAILED if result.failed else CheckStatus.INCONCLUSIVE if reasons else CheckStatus.COMPLETE
    if result.failed:
        reasons.append("An unexpected survey/resource failure occurred; raw exception text was suppressed.")
    return CheckReport(findings[:MAX_NETWORK_FINDINGS], status, " ".join(reasons))


def observation(
    item: PortObservation,
    rule: str,
    title: str,
    description: str,
    details: tuple[str, ...],
    remediation: str,
    confidence: Confidence = Confidence.OBSERVATION,
) -> Finding:
    """Construct minimal TCP evidence without raw greeting bytes or a guessed CVSS."""
    return Finding(
        rule,
        title,
        Severity.INFO,
        confidence,
        description,
        Evidence("TCP", item.endpoint, details),
        remediation,
        (NETWORK_REFERENCE,),
    )
