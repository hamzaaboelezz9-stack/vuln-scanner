"""Concurrent orchestration; incomplete coverage is never a clean security result."""

import logging
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable
from uuid import UUID

from scanner.checks.base import BaseCheck, CheckRegistry, CheckReport, registry
from scanner.checks.network.survey import NetworkSurvey
from scanner.core.config import MAX_SELECTED_CHECKS, ScanConfig
from scanner.core.errors import CheckSkipped, LimitReached, RobotsDenied, TransportError
from scanner.core.finding import Finding, Severity
from scanner.core.result import CheckOutcome, CheckStatus, ScanResult
from scanner.core.session import HTTPSession
from scanner.core.target import ScanMode, Target
from scanner.core.transport import TCPTransport, verified_tls_context
from scanner.safety.authorization import AuthorizedScope, ScopeGate
from scanner.safety.budget import CheckBudget, ScanControl
from scanner.safety.policy import ScopeError

LOG = logging.getLogger(__name__)
MAX_FINDINGS_PER_CHECK = 1000
ProgressCallback = Callable[[CheckOutcome, int, int], None]


@dataclass(frozen=True)
class EngineContext:
    """Per-check transports share one immutable scope and scan-wide controller."""

    target: Target
    scan_id: UUID
    config: ScanConfig
    scope: AuthorizedScope
    http: HTTPSession
    tcp: TCPTransport
    budget: CheckBudget
    network: NetworkSurvey | None = None


class ScanEngine:
    """Execute trusted registered checks after selection, configuration and authorization."""

    def __init__(self, gate: ScopeGate, config: ScanConfig | None = None, checks: CheckRegistry | None = None) -> None:
        """Use injected registries for deterministic tests and explicit plugin loading."""
        self.gate, self.config = gate, config or ScanConfig()
        self.registry = checks if checks is not None else registry

    def _run_check(
        self, check: BaseCheck, scope: AuthorizedScope, control: ScanControl, network: NetworkSurvey | None = None
    ) -> tuple[CheckOutcome, tuple[Finding, ...]]:
        try:
            control.checkpoint()
            budget = control.for_check(check.info.max_operations)
            tcp = TCPTransport(scope, self.config, budget)
            http = HTTPSession(tcp, self.config)
            context = EngineContext(scope.target, scope.scan_id, self.config, scope, http, tcp, budget, network)
            returned = check.run(context)
            if not isinstance(returned, (CheckReport, Sequence)):
                raise ValueError("Checks must return a bounded sequence or CheckReport.")
            if not isinstance(returned, CheckReport) and len(returned) > MAX_FINDINGS_PER_CHECK:
                raise ValueError("Check exceeded the findings limit.")
            report = returned if isinstance(returned, CheckReport) else CheckReport(tuple(returned))
            if len(report.findings) > MAX_FINDINGS_PER_CHECK:
                raise ValueError("Check exceeded the findings limit.")
            status, reason = report.status, report.reason
            try:
                control.checkpoint()
            except LimitReached:
                status, reason = (
                    CheckStatus.INCONCLUSIVE,
                    "Scan was cancelled or its deadline elapsed during this check.",
                )
            limitations = http.limitations()
            if status is CheckStatus.COMPLETE and limitations:
                status, reason = CheckStatus.INCONCLUSIVE, " ".join(limitations)
            return CheckOutcome(check.info.name, status, reason), report.findings
        except CheckSkipped:
            return CheckOutcome(
                check.info.name,
                CheckStatus.SKIPPED,
                "Check reported an unsupported target or runtime; manual review is required.",
            ), ()
        except RobotsDenied:
            return CheckOutcome(
                check.info.name, CheckStatus.SKIPPED, "Operator-enabled robots policy prevented this check."
            ), ()
        except ScopeError:
            return CheckOutcome(
                check.info.name, CheckStatus.INCONCLUSIVE, "The connection policy blocked a requested destination."
            ), ()
        except TransportError as error:
            # Our exception class names convey categories without logging remote exception text.
            return CheckOutcome(
                check.info.name,
                CheckStatus.INCONCLUSIVE,
                f"{type(error).__name__}: an approved operation failed or a safety limit was reached.",
            ), ()
        except Exception:
            LOG.error("Check %s failed; exception text suppressed to protect target data.", check.info.name)
            return CheckOutcome(
                check.info.name, CheckStatus.FAILED, "Unexpected check error; no clean result is implied."
            ), ()

    def run(
        self,
        target: Target,
        public_permission: bool = False,
        aggressive_permission: bool = False,
        ports: tuple[int, ...] = (),
        progress: ProgressCallback | None = None,
        control: ScanControl | None = None,
    ) -> ScanResult:
        """Run bounded worker concurrency and return deterministic findings plus coverage."""
        selected = self.registry.create(target.mode, self.config.checks)
        if not selected:
            raise ValueError("No checks are registered for this mode; scanning has not been implemented for it.")
        if len(selected) > MAX_SELECTED_CHECKS:
            raise ValueError("At most 64 checks may execute in one scan.")
        # Fail invalid CA configuration before authorization or any target-service work.
        verified_tls_context(self.config.ca_bundle)
        active_control = control or ScanControl(self.config, aggressive_permission)
        if control is not None:
            # A prebuilt controller is allowed for cancellation and virtual-time tests,
            # but its original limits/permissions must match this engine's configuration.
            if control.config != self.config or control.aggressive_permission is not aggressive_permission:
                raise ValueError("Injected controller does not match scan limits or permission.")
        active_control.claim()
        gate = ScopeGate(
            self.gate.state,
            self.gate.allowlist,
            self.gate.cloud,
            self.gate.resolver,
            min(self.gate.max_hosts, self.config.max_hosts),
        )
        scope = gate.authorize(target, public_permission, ports)
        network = None
        if target.mode is ScanMode.NETWORK:
            if len(scope.ports) > 1000 or len(scope.addresses) * len(scope.ports) > self.config.max_operations:
                raise ValueError("Selected network matrix exceeds the 1000-port or scan operation budget.")
            network = NetworkSurvey(scope, any(check.info.name in {"services", "cves"} for check in selected))
        result = ScanResult(
            scope.scan_id,
            target,
            limits=self.config.public_limits(),
            approved_addresses=scope.addresses,
            approved_ports=scope.ports,
        )
        pool = ThreadPoolExecutor(max_workers=min(self.config.workers, len(selected)), thread_name_prefix="vulnscan")
        try:
            futures = {
                pool.submit(self._run_check, check, scope, active_control, network): check.info.name
                for check in selected
            }
            for completed, future in enumerate(as_completed(futures), start=1):
                outcome, findings = future.result()
                result.outcomes.append(outcome)
                result.findings.extend(findings)
                if progress is not None:
                    try:
                        progress(outcome, completed, len(selected))
                    except Exception:
                        LOG.warning("Progress callback failed; scan processing continued.")
        except BaseException:
            active_control.cancel()
            raise
        finally:
            # Running socket operations are finite. Python cannot forcibly stop an
            # arbitrary in-process plugin; only trusted local plugins may register.
            pool.shutdown(wait=True, cancel_futures=True)
            result.attack_surface = network.summary() if network is not None else None
            result.operation_counts = active_control.counts()
            result.finish()
        result.outcomes.sort(key=lambda item: item.check)
        severity_order = {severity: index for index, severity in enumerate(Severity)}
        result.findings.sort(key=lambda item: (severity_order[item.severity], item.rule_id, item.evidence.endpoint))
        return result
