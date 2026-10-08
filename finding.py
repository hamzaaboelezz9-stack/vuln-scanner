"""Evidence-backed findings with explicit confidence and optional CVSS."""

import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit

from scanner.core.cvss import CVSS31
from scanner.utils.evidence import safe_text

MAX_OBSERVATIONS = 12
MAX_REFERENCES = 8
RULE_ID_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{1,63}\Z")
METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TCP", "TLS", "ICMP"})


class Severity(str, Enum):
    """Report severity, independent of certainty."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """Whether evidence establishes the reported issue or needs verification."""

    CONFIRMED = "confirmed"
    POTENTIAL = "needs-manual-verification"
    OBSERVATION = "observation"


@dataclass(frozen=True)
class Evidence:
    """Minimal request/response metadata; never an entire response body."""

    method: str
    endpoint: str
    observations: tuple[str, ...]
    status_code: int | None = None

    def __post_init__(self) -> None:
        """Bound and sanitize every persisted observation."""
        if self.method not in METHODS:
            raise ValueError("Unsupported evidence method.")
        if self.status_code is not None and (type(self.status_code) is not int or not 100 <= self.status_code <= 599):
            raise ValueError("Invalid HTTP status code.")
        if not self.observations or len(self.observations) > MAX_OBSERVATIONS:
            raise ValueError("Evidence requires 1–12 observations.")
        object.__setattr__(self, "endpoint", safe_text(self.endpoint))
        object.__setattr__(self, "observations", tuple(safe_text(item) for item in self.observations))


@dataclass(frozen=True)
class Finding:
    """One issue with remediation, evidence and reproducible scoring inputs."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: Evidence
    remediation: str
    references: tuple[str, ...] = ()
    cvss: CVSS31 | None = None

    def __post_init__(self) -> None:
        """Validate identifiers and remove common secrets from narrative fields."""
        if not RULE_ID_PATTERN.fullmatch(self.rule_id):
            raise ValueError("Invalid finding rule ID.")
        object.__setattr__(self, "severity", Severity(self.severity))
        object.__setattr__(self, "confidence", Confidence(self.confidence))
        for key in ("title", "description", "remediation"):
            if not getattr(self, key).strip():
                raise ValueError(f"Finding {key} is required.")
            object.__setattr__(self, key, safe_text(getattr(self, key)))
        if len(self.references) > MAX_REFERENCES:
            raise ValueError("Too many references.")
        for reference in self.references:
            parsed = urlsplit(reference)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("References require absolute HTTPS URLs without credentials.")
        object.__setattr__(self, "references", tuple(self.references))

    def to_dict(self) -> dict[str, object]:
        """Return JSON-compatible fields without hidden scoring assumptions."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "description": self.description,
            "evidence": {
                "method": self.evidence.method,
                "endpoint": self.evidence.endpoint,
                "status_code": self.evidence.status_code,
                "observations": list(self.evidence.observations),
            },
            "remediation": self.remediation,
            "references": list(self.references),
            "cvss": {"version": "3.1", "vector": self.cvss.vector, "score": self.cvss.score} if self.cvss else None,
        }
