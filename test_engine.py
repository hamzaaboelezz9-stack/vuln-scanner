"""The orchestration layer is exercised with explicit diagnostic test plugins."""

import logging
from pathlib import Path
from threading import Barrier, Lock
from typing import Callable, Sequence

import pytest

from scanner.checks.base import BaseCheck, CheckContext, CheckInfo, CheckRegistry, CheckReport
from scanner.core.config import ScanConfig
from scanner.core.engine import ScanEngine
from scanner.core.errors import CheckSkipped
from scanner.core.finding import Confidence, Evidence, Finding, Severity
from scanner.core.result import CheckOutcome, CheckStatus
from scanner.core.target import ScanMode, Target
from scanner.safety.authorization import ScopeGate
from scanner.safety.budget import ScanControl
from scanner.safety.policy import ScopeError
from scanner.safety.resolver import Resolution
from scanner.safety.state import AuthorizationStore
from tests.lab import serve_lab

Diagnostic = Callable[[CheckContext], Sequence[Finding] | CheckReport]


def add_check(
    registry: CheckRegistry, name: str, callback: Diagnostic, maximum: int = 10, mode: ScanMode = ScanMode.WEB
) -> None:
    """Register an isolated diagnostic plugin without altering the built-in check registry."""

    @registry.register(CheckInfo(name, mode, "Synthetic transport diagnostic", maximum))
    class DiagnosticCheck(BaseCheck):
        """Invoke a bounded test callback through the real engine context."""

        def run(self, context: CheckContext) -> Sequence[Finding] | CheckReport:
            """Return only synthetic test observations or explicit coverage status."""
            return callback(context)


def observation(context: CheckContext) -> Finding:
    """Create an informational assertion fixture, never a claimed vulnerability."""
    return Finding(
        "test.observation",
        "Synthetic observation",
        Severity.INFO,
        Confidence.OBSERVATION,
        "Synthetic test evidence.",
        Evidence("GET", context.target.display, ("Fixture returned its fixed content.",)),
        "No remediation; this is an informational test fixture.",
    )


def test_failure_isolation_progress_and_partial_findings(
    state: AuthorizationStore, caplog: pytest.LogCaptureFixture
) -> None:
    """One failed plugin and callback do not erase other checks or expose exceptions."""
    registry = CheckRegistry()

    def success(context: CheckContext) -> CheckReport:
        assert context.http.request(context.target.url).status_code == 200
        return CheckReport((observation(context),), CheckStatus.INCONCLUSIVE, "Synthetic partial coverage.")

    def failed(context: CheckContext) -> CheckReport:
        raise ValueError("synthetic-secret-exception")

    def skipped(context: CheckContext) -> CheckReport:
        raise CheckSkipped("synthetic-secret-skipped")

    def progress(outcome: CheckOutcome, completed: int, total: int) -> None:
        raise RuntimeError("synthetic-secret-progress")

    add_check(registry, "success", success)
    add_check(registry, "failure", failed)
    add_check(registry, "skipped", skipped)
    with serve_lab() as lab:
        caplog.set_level(logging.DEBUG)
        target = Target.web(lab.url + "/?token=synthetic-secret-query")
        gate = ScopeGate(state, resolver=lambda _: Resolution(("127.0.0.1",)))
        result = ScanEngine(gate, checks=registry).run(target, progress=progress)
        assert [outcome.check for outcome in result.outcomes] == ["failure", "skipped", "success"]
        assert {outcome.status for outcome in result.outcomes} == {
            CheckStatus.FAILED,
            CheckStatus.SKIPPED,
            CheckStatus.INCONCLUSIVE,
        }
        assert len(result.findings) == 1 and result.ended_at is not None
        assert result.operation_counts["HTTP"] == 1
        assert "synthetic-secret" not in caplog.text and "synthetic-secret" not in str(result.to_dict())


def test_empty_or_invalid_registry_fails_before_authorization(state: AuthorizationStore) -> None:
    """No registered checks is an unsupported mode, never a clean zero-finding scan."""
    gate = ScopeGate(state)
    with pytest.raises(ValueError, match="No checks"):
        ScanEngine(gate, checks=CheckRegistry()).run(Target.web("http://localhost"))
    with pytest.raises(ValueError, match="Unknown"):
        ScanEngine(gate, ScanConfig(checks=("missing",)), CheckRegistry()).run(Target.web("http://localhost"))
    assert not (state.directory / "scans.log").exists()


def test_global_and_declared_check_limits_preserve_incomplete_coverage(state: AuthorizationStore) -> None:
    """Connection caps produce inconclusive coverage instead of extra requests."""
    registry = CheckRegistry()

    def twice(context: CheckContext) -> tuple[Finding, ...]:
        context.http.request(context.target.url)
        context.http.request(context.target.url)
        return ()

    add_check(registry, "limited", twice, maximum=1)
    with serve_lab() as lab:
        gate = ScopeGate(state, resolver=lambda _: Resolution(("127.0.0.1",)))
        result = ScanEngine(gate, checks=registry).run(Target.web(lab.url))
        assert len(lab.requests) == result.operation_counts["HTTP"] == 1
        assert result.outcomes[0].status is CheckStatus.INCONCLUSIVE


def test_automatic_content_coverage_and_header_only_mode(state: AuthorizationStore) -> None:
    """Truncated content is partial; header-only checks need not read target bodies."""
    registry = CheckRegistry()

    def body(context: CheckContext) -> tuple[Finding, ...]:
        context.http.request(context.target.url + "/large")
        return ()

    def headers(context: CheckContext) -> tuple[Finding, ...]:
        context.http.request(context.target.url + "/compressed", read_body=False)
        return ()

    add_check(registry, "content", body)
    add_check(registry, "headers_only", headers)
    with serve_lab() as lab:
        gate = ScopeGate(state, resolver=lambda _: Resolution(("127.0.0.1",)))
        result = ScanEngine(gate, ScanConfig(max_response_bytes=256), registry).run(Target.web(lab.url))
        assert {item.check: item.status for item in result.outcomes} == {
            "content": CheckStatus.INCONCLUSIVE,
            "headers_only": CheckStatus.COMPLETE,
        }


def test_workers_share_one_limiter(state: AuthorizationStore) -> None:
    """Multiple plugin workers can overlap while HTTP attempts remain globally spaced."""
    registry, barrier, lock = CheckRegistry(), Barrier(2), Lock()
    active, peak = [0], [0]

    def callback(context: CheckContext) -> tuple[Finding, ...]:
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        barrier.wait(timeout=2)
        context.http.request(context.target.url)
        with lock:
            active[0] -= 1
        return ()

    for index in range(4):
        add_check(registry, f"worker_{index}", callback)
    with serve_lab() as lab:
        gate = ScopeGate(state, resolver=lambda _: Resolution(("127.0.0.1",)))
        result = ScanEngine(gate, ScanConfig(workers=2), registry).run(Target.web(lab.url))
        assert peak[0] == 2 and result.operation_counts["HTTP"] == 4
        assert all(item.status is CheckStatus.COMPLETE for item in result.outcomes)


def test_authorization_and_controller_validation_before_io(state: AuthorizationStore) -> None:
    """Plugins cannot be scheduled without scope approval and matching runtime permissions."""
    registry = CheckRegistry()
    add_check(registry, "noop", lambda _: ())
    engine = ScanEngine(ScopeGate(state), checks=registry)
    with pytest.raises(ScopeError):
        engine.run(Target.web("http://169.254.169.254"))
    with pytest.raises(ValueError, match="controller"):
        engine.run(Target.web("http://localhost"), control=ScanControl(ScanConfig(max_operations=1)))
    with pytest.raises(PermissionError):
        ScanEngine(ScopeGate(state), ScanConfig(rate_limit=11), registry).run(Target.web("http://localhost"))


def test_cancelled_control_produces_inconclusive_checks(state: AuthorizationStore) -> None:
    """Cancellation before scheduling still records approved scope without target requests."""
    registry = CheckRegistry()
    add_check(registry, "noop", lambda _: ())
    control = ScanControl(ScanConfig())
    control.cancel()
    result = ScanEngine(ScopeGate(state), checks=registry).run(Target.web("http://localhost"), control=control)
    assert result.outcomes[0].status is CheckStatus.INCONCLUSIVE
    assert sum(result.operation_counts.values()) == 0
    with pytest.raises(ValueError, match="only one"):
        ScanEngine(ScopeGate(state), checks=registry).run(Target.web("http://localhost"), control=control)


def test_configured_host_cap_and_bad_ca_fail_closed(state: AuthorizationStore, tmp_path: Path) -> None:
    """Engine limits restrict a wider gate; invalid trust files cannot trigger target I/O."""
    registry = CheckRegistry()
    add_check(registry, "noop", lambda _: ())
    gate = ScopeGate(state, max_hosts=256)
    add_check(registry, "noop_net", lambda _: (), mode=ScanMode.NETWORK)
    with pytest.raises(ScopeError, match="Host budget|host budget"):
        ScanEngine(gate, ScanConfig(max_hosts=1), registry).run(Target.net("192.168.1.0/30"), ports=(80,))
    with pytest.raises(OSError):
        ScanEngine(gate, ScanConfig(ca_bundle=str(tmp_path / "absent.pem")), registry).run(
            Target.web("http://localhost")
        )
