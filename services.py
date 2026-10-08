"""Passive, bounded greeting fingerprints; no port-only identity or version guessing."""

from scanner.checks.base import BaseCheck, CheckContext, CheckInfo, CheckReport, register_check
from scanner.checks.network.common import MAX_NETWORK_FINDINGS, observation, report, survey_result
from scanner.core.config import MAX_OPERATIONS
from scanner.core.network import BannerState, PortState
from scanner.core.target import ScanMode


@register_check(
    CheckInfo(
        "services",
        ScanMode.NETWORK,
        "Passive greeting protocol/product/version recognition without login or probes",
        MAX_OPERATIONS,
    )
)
class ServicesCheck(BaseCheck):
    """Distinguish advertised software from authenticated identity and protocol revisions."""

    def run(self, context: CheckContext) -> CheckReport:
        """Report constrained identifiers, omitting complete greetings and arbitrary text."""
        result = survey_result(context)
        findings = []
        notes = []
        for item in result.observations:
            if item.state is not PortState.OPEN:
                continue
            if item.service is None:
                notes.append("Some open listeners had no recognized passive greeting; protocol/product remain unknown.")
                continue
            if item.banner_state in {BannerState.TIMEOUT, BannerState.TRUNCATED, BannerState.ERROR}:
                notes.append(
                    "Some recognized greetings were incomplete, truncated or interrupted; manual identity review is required."
                )
            identity = item.service
            details = ["Advertised protocol: " + identity.protocol]
            if identity.product:
                details.append("Advertised product: " + identity.product)
            if identity.version:
                details.append("Advertised software version: " + identity.version)
            if len(findings) <= MAX_NETWORK_FINDINGS:
                findings.append(
                    observation(
                        item,
                        "network.service_identity",
                        "Passive service identity advertised",
                        "A greeting matched a bounded built-in signature. Banners can be spoofed and distribution packages may backport fixes. No login, HTTP request, database query or service command was sent. [Needs manual verification] for installed product/version and vulnerability applicability.",
                        tuple(details),
                        "Verify installed package versions and vendor patch/backport status through authorized administrative inventory. Restrict unnecessary greeting detail, while prioritizing patching and access control over banner hiding.",
                    )
                )
        return report(result, tuple(findings), tuple(dict.fromkeys(notes)))
