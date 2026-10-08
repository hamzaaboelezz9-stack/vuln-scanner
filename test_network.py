"""Real local connects verify shared surveys, silence, bounded greetings and scope."""

import errno
import json
import socket
import time

import pytest

from scanner.checks.network import load_network_checks
from scanner.core.config import ScanConfig
from scanner.core.engine import EngineContext, ScanEngine
from scanner.core.network import BannerState, PortState
from scanner.core.session import HTTPSession
from scanner.core.target import Target
from scanner.core.transport import TCPTransport
from scanner.safety.authorization import ScopeGate
from scanner.safety.budget import ScanControl
from scanner.safety.policy import ScopeError
from scanner.safety.state import AuthorizationStore
from tests.network_lab import greeting_lab, unused_port
from tests.web_support import rule_registry


def net_context(state: AuthorizationStore, ports: tuple[int, ...], config: ScanConfig | None = None) -> EngineContext:
    """Construct real numeric loopback transports with virtual operation pacing."""
    config = config or ScanConfig(timeout=0.2, network_banner_seconds=0.15)
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    scope = ScopeGate(state).authorize(Target.net("127.0.0.1"), ports=ports)
    budget = ScanControl(config, clock=lambda: clock[0], sleep=sleep).for_check(config.max_operations)
    tcp = TCPTransport(scope, config, budget)
    return EngineContext(scope.target, scope.scan_id, config, scope, HTTPSession(tcp, config), tcp, budget)


def test_shared_survey_one_connect_per_pair_no_command(
    state: AuthorizationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All four checks share actual connections and never re-resolve target addresses."""
    with greeting_lab() as lab:
        closed = unused_port()
        config = ScanConfig(timeout=0.5, network_banner_seconds=0.15)
        clock = [0.0]

        def sleep(seconds: float) -> None:
            clock[0] += seconds

        control = ScanControl(config, clock=lambda: clock[0], sleep=sleep)

        def forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("Numeric target must not trigger socket DNS.")

        monkeypatch.setattr(socket, "getaddrinfo", forbidden)
        result = ScanEngine(ScopeGate(state), config, rule_registry(*load_network_checks())).run(
            Target.net("127.0.0.1"), ports=(lab.port, closed), control=control
        )
        assert result.operation_counts == {"HTTP": 0, "TCP": 2, "TLS": 0}
        assert lab.connections == 1 and not any(lab.received)
        assert all(item.status.value != "failed" for item in result.outcomes)
        assert next(item for item in result.outcomes if item.check == "cves").status.value == "skipped"
        assert result.attack_surface and result.attack_surface["observed_pairs"] == 2
        assert result.attack_surface["application_bytes_sent"] == 0
        assert result.attack_surface["open_ports"][0]["service"]["advertised_version"] == "9.8p1"
        assert {"network.tcp_response", "network.open_port", "network.service_identity"} == {
            item.rule_id for item in result.findings
        }
        assert "synthetic" not in json.dumps(result.to_dict())
        assert all(item.cvss is None for item in result.findings)


def test_fragmented_greeting_and_immediate_close(state: AuthorizationStore) -> None:
    """Slow fragments form one greeting; EOF without content still confirms an open port."""
    with greeting_lab((b"SSH-2.0-", b"OpenSSH_9.8", b"p1\r\n"), delay=0.01) as lab:
        probe = net_context(state, (lab.port,)).tcp.probe_port("127.0.0.1", lab.port)
        assert probe.state is PortState.OPEN and probe.banner_state is BannerState.COMPLETE
        assert probe.banner == b"SSH-2.0-OpenSSH_9.8p1\r\n"
    with greeting_lab(()) as lab:
        probe = net_context(state, (lab.port,)).tcp.probe_port("127.0.0.1", lab.port, False)
        assert probe.state is PortState.OPEN and probe.banner_state is BannerState.NOT_READ


def test_silent_and_overlong_greeting_limits(state: AuthorizationStore) -> None:
    """Silence cannot close a known listener; overflowing greeting bytes are truncated."""
    with greeting_lab((), silent_seconds=1) as lab:
        before = time.monotonic()
        probe = net_context(state, (lab.port,)).tcp.probe_port("127.0.0.1", lab.port)
        assert time.monotonic() - before < 0.7
        assert probe.state is PortState.OPEN and probe.banner_state is BannerState.TIMEOUT and not probe.banner
    with greeting_lab((b"X" * 20000,)) as lab:
        probe = net_context(state, (lab.port,)).tcp.probe_port("127.0.0.1", lab.port)
        assert probe.banner_state is BannerState.TRUNCATED and len(probe.banner) == 4096
        assert "XXXXX" not in repr(probe)


@pytest.mark.parametrize(
    "number,expected",
    [
        (errno.ECONNREFUSED, PortState.REFUSED),
        (errno.ETIMEDOUT, PortState.TIMEOUT),
        (errno.EHOSTUNREACH, PortState.UNREACHABLE),
        (errno.ENETUNREACH, PortState.UNREACHABLE),
        (errno.EACCES, PortState.ERROR),
    ],
)
def test_connect_error_classification(
    state: AuthorizationStore, monkeypatch: pytest.MonkeyPatch, number: int, expected: PortState
) -> None:
    """Kernel outcomes remain distinct without exposing remote exception strings."""
    context = net_context(state, (33333,))

    def fail(*args: object, **kwargs: object) -> None:
        raise OSError(number, "synthetic-private-error")

    monkeypatch.setattr(context.tcp, "_dial", fail)
    probe = context.tcp.probe_port("127.0.0.1", 33333)
    assert probe.state is expected and "synthetic-private" not in repr(probe)
    assert context.budget.used == 1


def test_scope_and_matrix_refusal_before_connection(state: AuthorizationStore) -> None:
    """Network methods cannot widen ports/addresses or start an oversized matrix."""
    with greeting_lab() as lab:
        context = net_context(state, (lab.port,))
        for host, port in (("169.254.169.254", lab.port), ("127.0.0.1", unused_port())):
            with pytest.raises(ScopeError):
                context.tcp.probe_port(host, port)
        assert context.budget.used == 0 and lab.connections == 0
        config = ScanConfig(max_operations=1)
        with pytest.raises(ValueError):
            ScanEngine(ScopeGate(state), config, rule_registry(*load_network_checks())).run(
                Target.net("127.0.0.1"), ports=(lab.port, unused_port())
            )
        assert lab.connections == 0


def test_timeout_matrix_is_unknown_not_closed(state: AuthorizationStore, monkeypatch: pytest.MonkeyPatch) -> None:
    """A simulated filtered host remains in scope and does not become a clean host pass."""

    def timeout(*args: object, **kwargs: object) -> None:
        raise TimeoutError("synthetic")

    monkeypatch.setattr(TCPTransport, "_dial", timeout)
    config = ScanConfig(checks=("discovery", "ports"))
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    result = ScanEngine(ScopeGate(state), config, rule_registry(*load_network_checks())).run(
        Target.net("127.0.0.1/32"), ports=(22, 443), control=ScanControl(config, clock=lambda: clock[0], sleep=sleep)
    )
    assert result.operation_counts["TCP"] == 2 and not result.findings
    assert all(item.status.value == "inconclusive" for item in result.outcomes)
    assert result.attack_surface["hosts"][0]["tcp_response"] == "unknown"
    assert result.attack_surface["hosts"][0]["counts"]["no-response"] == 2
    assert {item["port"] for item in result.attack_surface["uncertain_ports"]} == {22, 443}


def test_only_port_checks_skip_passive_read_delay(state: AuthorizationStore) -> None:
    """Port-only selection does not spend a greeting window waiting on silent services."""
    with greeting_lab((), silent_seconds=1) as lab:
        config = ScanConfig(checks=("ports",), timeout=0.2, network_banner_seconds=0.2)
        before = time.monotonic()
        result = ScanEngine(ScopeGate(state), config, rule_registry(*load_network_checks())).run(
            Target.net("127.0.0.1"), ports=(lab.port,)
        )
        assert time.monotonic() - before < 0.18
        assert result.attack_surface["open_ports"][0]["banner"] == "not-read"


@pytest.mark.parametrize(
    "setting", [{"network_banner_seconds": 0}, {"network_banner_seconds": True}, {"cve_cache": "\0unsafe"}]
)
def test_invalid_network_config(setting: dict[str, object]) -> None:
    """Network settings have finite bounds and cache paths cannot contain controls."""
    with pytest.raises(ValueError):
        ScanConfig(**setting)


def test_survey_worker_bound_and_complete_thousand_port_support(
    state: AuthorizationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A thousand jobs use a small rolling worker set rather than one future per target."""
    from threading import Event, Lock

    from scanner.core.network import TCPProbe

    counts = [0, 0]
    lock = Lock()

    def probe(self: TCPTransport, hostname: str, port: int, read_banner: bool = True) -> TCPProbe:
        self.scope.permit(hostname, port)
        self.budget.begin("TCP")
        with lock:
            counts[0] += 1
            counts[1] = max(counts)
        Event().wait(0.001)
        with lock:
            counts[0] -= 1
        return TCPProbe(hostname, port, PortState.REFUSED)

    monkeypatch.setattr(TCPTransport, "probe_port", probe)
    config = ScanConfig(workers=2, checks=("discovery", "ports"), max_operations=1000)
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    result = ScanEngine(ScopeGate(state), config, rule_registry(*load_network_checks())).run(
        Target.net("127.0.0.1"),
        ports=tuple(range(1, 1001)),
        control=ScanControl(config, clock=lambda: clock[0], sleep=sleep),
    )
    assert counts[1] == 2 and result.operation_counts["TCP"] == 1000
    assert result.attack_surface["observed_pairs"] == 1000 and not result.attack_surface["incomplete"]
    assert all(item.status.value == "complete" for item in result.outcomes)


def test_cancellation_preserves_completed_pairs_and_stops_new_jobs(
    state: AuthorizationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Already-observed TCP responses survive a shared cancellation signal."""
    from scanner.core.network import TCPProbe

    def probe(self: TCPTransport, hostname: str, port: int, read_banner: bool = True) -> TCPProbe:
        self.budget.begin("TCP")
        if port == 2:
            self.budget.control.cancel()
        return TCPProbe(hostname, port, PortState.REFUSED)

    monkeypatch.setattr(TCPTransport, "probe_port", probe)
    config = ScanConfig(workers=1, checks=("discovery", "ports"))
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    result = ScanEngine(ScopeGate(state), config, rule_registry(*load_network_checks())).run(
        Target.net("127.0.0.1"), ports=(1, 2, 3, 4), control=ScanControl(config, clock=lambda: clock[0], sleep=sleep)
    )
    assert result.operation_counts["TCP"] == 2 and result.attack_surface["observed_pairs"] == 2
    assert result.attack_surface["incomplete"] and any(
        item.rule_id == "network.tcp_response" for item in result.findings
    )
    assert all(item.status.value == "inconclusive" for item in result.outcomes)


def test_unexpected_worker_failure_never_becomes_silent_host(
    state: AuthorizationStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A trusted worker bug is a failed survey; no raw exception text is retained."""

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic-private-failure")

    monkeypatch.setattr(TCPTransport, "probe_port", broken)
    config = ScanConfig(checks=("discovery", "ports", "services"))
    result = ScanEngine(ScopeGate(state), config, rule_registry(*load_network_checks())).run(
        Target.net("127.0.0.1"), ports=(22,)
    )
    assert result.attack_surface["failed"] and all(item.status.value == "failed" for item in result.outcomes)
    assert "synthetic-private-failure" not in str(result.to_dict()) + caplog.text
