"""Construct real authorized check contexts and isolated registries for web tests."""

from scanner.checks.base import BaseCheck, CheckRegistry
from scanner.core.config import ScanConfig
from scanner.core.engine import EngineContext
from scanner.core.session import HTTPSession
from scanner.core.target import Target
from scanner.core.transport import TCPTransport
from scanner.safety.authorization import ScopeGate
from scanner.safety.budget import ScanControl
from scanner.safety.resolver import Resolution
from scanner.safety.state import AuthorizationStore


def web_context(state: AuthorizationStore, url: str, config: ScanConfig | None = None) -> EngineContext:
    """Use virtual pacing with real loopback socket I/O for fast, bounded rule tests."""
    config = config or ScanConfig(timeout=0.3)
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    scope = ScopeGate(state, resolver=lambda _: Resolution(("127.0.0.1",))).authorize(Target.web(url))
    control = ScanControl(config, clock=lambda: clock[0], sleep=sleep)
    budget = control.for_check(config.max_operations)
    tcp = TCPTransport(scope, config, budget)
    return EngineContext(scope.target, scope.scan_id, config, scope, HTTPSession(tcp, config), tcp, budget)


def rule_registry(*classes: type[BaseCheck]) -> CheckRegistry:
    """Register selected rule classes without relying on global import order."""
    registry = CheckRegistry()
    for cls in classes:
        registry.register(cls.info)(cls)
    return registry
