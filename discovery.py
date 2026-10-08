"""TCP-response host discovery; silence never proves a host is absent."""

from scanner.checks.base import BaseCheck, CheckContext, CheckInfo, CheckReport, register_check
from scanner.checks.network.common import MAX_NETWORK_FINDINGS, observation, report, survey_result
from scanner.core.config import MAX_OPERATIONS
from scanner.core.network import PortState
from scanner.core.target import ScanMode


@register_check(
    CheckInfo(
        "discovery",
        ScanMode.NETWORK,
        "TCP-connect response discovery without raw sockets or ICMP privileges",
        MAX_OPERATIONS,
    )
)
class DiscoveryCheck(BaseCheck):
    """Summarize responses without skipping hosts based on an unreliable ping result."""

    def run(self, context: CheckContext) -> CheckReport:
        """Treat open/refused connects as observed TCP responses, possibly from a middlebox."""
        result = survey_result(context)
        findings = []
        responsive: set[str] = set()
        for item in result.observations:
            if item.address not in responsive and item.state in {PortState.OPEN, PortState.REFUSED}:
                responsive.add(item.address)
                if len(findings) <= MAX_NETWORK_FINDINGS:
                    findings.append(
                        observation(
                            item,
                            "network.tcp_response",
                            "TCP response observed",
                            "A connect succeeded or was refused. This establishes a response from the address/path, possibly a firewall or middlebox, not proof of end-host identity. No ICMP/raw SYN packet or application command was sent.",
                            (
                                "TCP outcome: " + item.state.value,
                                "Every authorized address remains eligible for selected-port probing regardless of this response.",
                            ),
                            "Maintain an accurate asset inventory and limit network exposure to the intended trust zones. Verify address ownership and any middlebox responses with the operator.",
                        )
                    )
        notes = (
            ()
            if len(responsive) == len(context.scope.addresses)
            else ("Some approved addresses had no conclusive TCP response; their presence remains unknown.",)
        )
        return report(result, tuple(findings), notes)
