"""Small explicit registry: imports register classes, never execute scans."""

import inspect
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Protocol, Sequence
from uuid import UUID

from scanner.core.finding import Finding
from scanner.core.result import CheckStatus
from scanner.core.target import ScanMode, Target

if TYPE_CHECKING:
    from scanner.checks.network.survey import NetworkSurvey
    from scanner.core.config import ScanConfig
    from scanner.core.session import HTTPSession
    from scanner.core.transport import TCPTransport
    from scanner.safety.authorization import AuthorizedScope
    from scanner.safety.budget import CheckBudget


class CheckContext(Protocol):
    """Typed capability contract supplied by the engine to trusted local checks."""

    target: Target
    scan_id: UUID
    config: "ScanConfig"
    scope: "AuthorizedScope"
    http: "HTTPSession"
    tcp: "TCPTransport"
    budget: "CheckBudget"
    network: "NetworkSurvey | None"


@dataclass(frozen=True)
class CheckReport:
    """Explicit partial coverage can retain already-observed findings."""

    findings: tuple[Finding, ...] = ()
    status: CheckStatus = CheckStatus.COMPLETE
    reason: str = ""

    def __post_init__(self) -> None:
        """Require validated findings and explanations for incomplete coverage."""
        object.__setattr__(self, "status", CheckStatus(self.status))
        object.__setattr__(self, "findings", tuple(self.findings))
        if any(not isinstance(item, Finding) for item in self.findings):
            raise ValueError("Check reports require Finding instances.")
        if self.status is not CheckStatus.COMPLETE and not self.reason:
            raise ValueError("Incomplete check reports require a reason.")


@dataclass(frozen=True)
class CheckInfo:
    """Public check identity and an estimated upper-bound operation budget."""

    name: str
    mode: ScanMode
    description: str
    max_operations: int

    def __post_init__(self) -> None:
        """Require stable names and positive, bounded operation estimates."""
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,31}", self.name):
            raise ValueError("Invalid check name.")
        object.__setattr__(self, "mode", ScanMode(self.mode))
        if not self.description.strip() or type(self.max_operations) is not int or self.max_operations < 1:
            raise ValueError("Checks require a description and positive operation budget.")


class BaseCheck(ABC):
    """A check receives approved context and returns structured evidence."""

    info: CheckInfo

    @abstractmethod
    def run(self, context: CheckContext) -> Sequence[Finding] | CheckReport:
        """Inspect an authorized target using context-provided transports."""


class CheckRegistry:
    """Register concrete classes and reject unknown or wrong-mode selections."""

    def __init__(self) -> None:
        """Create an independent registry, allowing isolated unit tests."""
        self._checks: dict[str, tuple[CheckInfo, type[BaseCheck]]] = {}

    def register(self, info: CheckInfo) -> Callable[[type[BaseCheck]], type[BaseCheck]]:
        """Return a decorator that attaches metadata and records a concrete class."""

        def decorator(cls: type[BaseCheck]) -> type[BaseCheck]:
            if not inspect.isclass(cls) or not issubclass(cls, BaseCheck) or inspect.isabstract(cls):
                raise TypeError("Only concrete BaseCheck subclasses may register.")
            if info.name in self._checks:
                raise ValueError(f"Duplicate check: {info.name}")
            cls.info = info
            self._checks[info.name] = (info, cls)
            return cls

        return decorator

    def create(self, mode: ScanMode, names: Sequence[str] | None = None) -> tuple[BaseCheck, ...]:
        """Instantiate selected checks; fail before execution on invalid names."""
        mode = ScanMode(mode)
        selected = (
            list(names)
            if names is not None
            else sorted(name for name, (info, _) in self._checks.items() if info.mode is mode)
        )
        if len(selected) != len(set(selected)):
            raise ValueError("A check must not be selected twice.")
        for name in selected:
            if name not in self._checks or self._checks[name][0].mode is not mode:
                raise ValueError(f"Unknown or incompatible check: {name}")
        return tuple(self._checks[name][1]() for name in selected)

    def describe(self) -> tuple[CheckInfo, ...]:
        """List immutable metadata in deterministic name order."""
        return tuple(self._checks[name][0] for name in sorted(self._checks))


registry = CheckRegistry()
register_check = registry.register
