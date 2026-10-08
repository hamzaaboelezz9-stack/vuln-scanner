"""TCP-connect enumeration with explicit refusal, timeout and unreachable outcomes."""

from scanner.checks.base import BaseCheck, CheckContext, CheckInfo, CheckReport, register_check
from scanner.checks.network.common import MAX_NETWORK_FINDINGS, observation, report, survey_result
from scanner.core.config import MAX_OPERATIONS
from scanner.core.finding import Confidence
from scanner.core.network import PortState
from scanner.core.target import ScanMode


@register_check(
    CheckInfo(
        "ports",
        ScanMode.NETWORK,
        "Concurrent bounded TCP-connect port survey with no application commands",
        MAX_OPERATIONS,
    )
)
class PortsCheck(BaseCheck):
    """Report open listeners as attack-surface inventory rather than vulnerabilities."""

    def run(self, context: CheckContext) -> CheckReport:
        """Use the shared survey and retain uncertain connection states in coverage."""
        result = survey_result(context)
        opened = [item for item in result.observations if item.state is PortState.OPEN]
        findings = tuple(
            observation(
                item,
                "network.open_port",
                "TCP listener accepted a connection",
                "A TCP handshake completed on this approved address and port. An open listener alone is not a vulnerability or evidence of an unauthenticated application action. Service identity is assessed separately.",
                ("TCP connect succeeded.", "No application bytes were transmitted."),
                "Review whether the listener is required, bind private services to the intended interface, restrict ingress with host/network firewalls, and enforce service authentication and patching.",
                Confidence.CONFIRMED,
            )
            for item in opened[: MAX_NETWORK_FINDINGS + 1]
        )
        notes = []
        if any(item.state not in {PortState.OPEN, PortState.REFUSED} for item in result.observations):
            notes.append(
                "Some ports had no response, an unreachable path or a local error; they were not labeled closed."
            )
        return report(result, findings, tuple(notes))
