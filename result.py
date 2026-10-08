"""Results preserve scan coverage: failure is never represented as a clean pass."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID

from scanner.core.finding import Finding, Severity
from scanner.core.target import Target
from scanner.utils.evidence import safe_text


class CheckStatus(str, Enum):
    """Outcome of executing a check, distinct from finding severity."""

    COMPLETE = "complete"
    SKIPPED = "skipped"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"


@dataclass(frozen=True)
class CheckOutcome:
    """Check coverage and a sanitized reason when coverage is incomplete."""

    check: str
    status: CheckStatus
    reason: str = ""

    def __post_init__(self) -> None:
        """Normalize status and bound diagnostics."""
        object.__setattr__(self, "status", CheckStatus(self.status))
        object.__setattr__(self, "check", safe_text(self.check))
        object.__setattr__(self, "reason", safe_text(self.reason))
        if self.status is not CheckStatus.COMPLETE and not self.reason:
            raise ValueError("Incomplete checks require a coverage explanation.")


@dataclass
class ScanResult:
    """Engine-owned aggregate; workers return findings instead of mutating it."""

    scan_id: UUID
    target: Target
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    outcomes: list[CheckOutcome] = field(default_factory=list)
    operation_counts: dict[str, int] = field(default_factory=dict)
    limits: dict[str, object] = field(default_factory=dict)
    approved_addresses: tuple[str, ...] = ()
    approved_ports: tuple[int, ...] = ()
    attack_surface: dict[str, object] | None = None

    def __post_init__(self) -> None:
        """Reject non-UUID identifiers and ambiguous local timestamps."""
        if not isinstance(self.scan_id, UUID) or self.started_at.utcoffset() is None:
            raise ValueError("Results require a UUID and timezone-aware start time.")
        if self.ended_at is not None:
            self.finish(self.ended_at)

    def finish(self, at: datetime | None = None) -> None:
        """Record completion only with an aware timestamp after the start."""
        at = at or datetime.now(timezone.utc)
        if at.utcoffset() is None or at < self.started_at:
            raise ValueError("Invalid scan completion timestamp.")
        self.ended_at = at

    def to_dict(self) -> dict[str, object]:
        """Serialize severity counts and explicit incomplete-check coverage."""
        return {
            "schema": "vulnscanner.result.v1",
            "scan_id": str(self.scan_id),
            "target": self.target.display,
            "mode": self.target.mode.value,
            "started_at": self.started_at.astimezone(timezone.utc).isoformat(),
            "ended_at": self.ended_at.astimezone(timezone.utc).isoformat() if self.ended_at else None,
            "counts": {
                severity.value: sum(item.severity is severity for item in self.findings) for severity in Severity
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "coverage": [
                {"check": outcome.check, "status": outcome.status.value, "reason": outcome.reason}
                for outcome in self.outcomes
            ],
            "operations": dict(self.operation_counts),
            "limits": dict(self.limits),
            "attack_surface": self.attack_surface,
            "approved_scope": {"addresses": list(self.approved_addresses), "ports": list(self.approved_ports)},
        }
