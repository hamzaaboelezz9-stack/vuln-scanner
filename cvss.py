"""CVSS v3.1 base scoring, following FIRST's published equations."""

import math
from dataclasses import dataclass, field

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0.0, "C": 1.0},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
CHANGED_SCOPE_PRIVILEGES = {"N": 0.85, "L": 0.68, "H": 0.5}
EXPLOITABILITY_COEFFICIENT = 8.22
UNCHANGED_IMPACT_COEFFICIENT = 6.42
CHANGED_IMPACT_COEFFICIENT = 7.52
CHANGED_IMPACT_OFFSET = 0.029
CHANGED_IMPACT_PENALTY = 3.25
CHANGED_IMPACT_POWER_OFFSET = 0.02
CHANGED_IMPACT_POWER = 15
CHANGED_SCOPE_MULTIPLIER = 1.08
MAX_SCORE = 10.0
ROUND_PRECISION = 100000
TENTH_PRECISION = 10000


def _roundup(value: float) -> float:
    # FIRST's integer method avoids raising 4.000000000000001 to 4.1.
    scaled = round(value * ROUND_PRECISION)
    if scaled % TENTH_PRECISION == 0:
        return scaled / ROUND_PRECISION
    return (math.floor(scaled / TENTH_PRECISION) + 1) / 10


@dataclass(frozen=True)
class CVSS31:
    """Validated base vector with a computed, never independently supplied score."""

    vector: str
    score: float = field(init=False)

    def __post_init__(self) -> None:
        """Reject missing, duplicate, unknown and non-base metrics."""
        parts = self.vector.split("/")
        if parts[0] != "CVSS:3.1" or len(parts) != len(WEIGHTS) + 1:
            raise ValueError("A complete CVSS:3.1 base vector is required.")
        metrics: dict[str, str] = {}
        for part in parts[1:]:
            pair = part.split(":")
            if len(pair) != 2 or pair[0] not in WEIGHTS or pair[0] in metrics:
                raise ValueError("Unknown or duplicate CVSS metric.")
            key, value = pair
            if value not in WEIGHTS[key]:
                raise ValueError("Invalid CVSS metric value.")
            metrics[key] = value
        weights = {key: WEIGHTS[key][value] for key, value in metrics.items()}
        changed = metrics["S"] == "C"
        if changed:
            weights["PR"] = CHANGED_SCOPE_PRIVILEGES[metrics["PR"]]
        iss = 1 - (1 - weights["C"]) * (1 - weights["I"]) * (1 - weights["A"])
        if changed:
            impact = CHANGED_IMPACT_COEFFICIENT * (iss - CHANGED_IMPACT_OFFSET)
            impact -= CHANGED_IMPACT_PENALTY * (iss - CHANGED_IMPACT_POWER_OFFSET) ** CHANGED_IMPACT_POWER
        else:
            impact = UNCHANGED_IMPACT_COEFFICIENT * iss
        exploitability = EXPLOITABILITY_COEFFICIENT * math.prod(weights[key] for key in ("AV", "AC", "PR", "UI"))
        total = (impact + exploitability) * (CHANGED_SCOPE_MULTIPLIER if changed else 1)
        object.__setattr__(self, "score", 0.0 if impact <= 0 else _roundup(min(total, MAX_SCORE)))
