"""A bounded, immutable report snapshot shared by all output formats."""

import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import UUID

from scanner.core.config import ScanConfig
from scanner.core.cvss import CVSS31
from scanner.core.finding import Confidence, Evidence, Finding, Severity
from scanner.core.network import BannerState, PortObservation, PortState, ServiceIdentity
from scanner.core.result import CheckOutcome, CheckStatus, ScanResult
from scanner.core.target import ScanMode, Target, validate_port
from scanner.safety.policy import canonical_ip
from scanner.utils.evidence import MAX_EVIDENCE_LENGTH, redact_url, safe_text

MAX_FINDINGS = 2048
MAX_CHECKS = 64
MAX_HOSTS = 4096
MAX_PORTS = 1000
MAX_SURFACE_PORTS = 1024
MAX_OPERATIONS = 200_000
CHECK_NAME = re.compile(r"[a-z][a-z0-9_]{1,31}\Z")
SEVERITY_ORDER = tuple(Severity)


class ReportError(ValueError):
    """A source result or export cannot be handled safely and consistently."""


def display_text(value: str) -> str:
    """Redact known secrets and remove terminal controls, surrogates and bidi overrides."""
    text = safe_text(value)
    return "".join(
        char if char in "\n\t" or unicodedata.category(char) not in {"Cc", "Cf", "Cs"} else " " for char in text
    )


def _object(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ReportError("Expected a JSON object with text keys.")
    return value


def _text(value: object, maximum: int = MAX_EVIDENCE_LENGTH) -> str:
    if not isinstance(value, str) or len(value) > maximum:
        raise ReportError("Missing or oversized text field.")
    return display_text(value)


def _integer(value: object, maximum: int = MAX_OPERATIONS) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ReportError("Invalid bounded integer field.")
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise ReportError("Expected a boolean field.")
    return value


def _list(value: object, maximum: int) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ReportError("Missing or oversized list field.")
    return value


def _time(value: object) -> datetime:
    text = _text(value, 64)
    at = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if at.utcoffset() is None:
        raise ReportError("Timestamps require a timezone.")
    return at.astimezone(timezone.utc)


def reference_url(value: object) -> str:
    """Allow inert HTTPS links only; drop queries/fragments and quote Markdown delimiters."""
    text = _text(value)
    if any(char.isspace() for char in text) or any(unicodedata.category(c) in {"Cc", "Cf"} for c in text):
        raise ReportError("Reference URL contains controls or whitespace.")
    parsed = urlsplit(text)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or "\\" in text:
        raise ReportError("Reference links must be HTTPS without credentials.")
    host = parsed.hostname.encode("idna").decode("ascii")
    host = f"[{host}]" if ":" in host else host
    if parsed.port is not None:
        validate_port(parsed.port)
        host += f":{parsed.port}"
    return urlunsplit(("https", host, quote(parsed.path, safe="/%:._~!$&'+,;=@-"), "", ""))


def _finding(value: object) -> Finding:
    item = _object(value)
    evidence = _object(item.get("evidence"))
    score = item.get("cvss")
    cvss = None
    if score is not None:
        fields = _object(score)
        if fields.get("version") != "3.1":
            raise ReportError("Only CVSS v3.1 base scores are supported.")
        cvss = CVSS31(_text(fields.get("vector"), 128))
        supplied = fields.get("score")
        if type(supplied) not in (float, int) or supplied != cvss.score:
            raise ReportError("Supplied CVSS score disagrees with its vector.")
    endpoint = _text(evidence.get("endpoint"))
    if endpoint.startswith(("http://", "https://")):
        endpoint = redact_url(endpoint)
    return Finding(
        _text(item.get("rule_id"), 64),
        _text(item.get("title")),
        Severity(item.get("severity")),
        Confidence(item.get("confidence")),
        _text(item.get("description")),
        Evidence(
            _text(evidence.get("method"), 8),
            endpoint,
            tuple(_text(text) for text in _list(evidence.get("observations"), 12)),
            evidence.get("status_code"),
        ),
        _text(item.get("remediation")),
        tuple(reference_url(url) for url in _list(item.get("references", []), 8)),
        cvss,
    )


def _outcome(value: object) -> CheckOutcome:
    item = _object(value)
    check = _text(item.get("check"), 32)
    if not CHECK_NAME.fullmatch(check):
        raise ReportError("Invalid check identity.")
    return CheckOutcome(check, CheckStatus(item.get("status")), _text(item.get("reason", "")))


@dataclass(frozen=True)
class SurfaceHost:
    """Numeric host and explicitly observed socket states, without raw greetings."""

    address: str
    response: str
    counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class Surface:
    """Validated minimal network inventory with visible collection/truncation limits."""

    planned: int
    observed: int
    incomplete: bool
    failed: bool
    hosts: tuple[SurfaceHost, ...]
    opened: tuple[PortObservation, ...]
    uncertain: tuple[PortObservation, ...]
    open_omitted: int
    uncertain_omitted: int

    def to_dict(self) -> dict[str, object]:
        """Serialize only recognized metadata, never arbitrary imported properties."""
        return {
            "kind": "passive-tcp-connect-survey",
            "planned_pairs": self.planned,
            "observed_pairs": self.observed,
            "incomplete": self.incomplete,
            "failed": self.failed,
            "hosts": [
                {"address": host.address, "tcp_response": host.response, "counts": dict(host.counts)}
                for host in self.hosts
            ],
            "open_ports": [port.to_dict() for port in self.opened],
            "uncertain_ports": [port.to_dict() for port in self.uncertain],
            "open_ports_omitted": self.open_omitted,
            "uncertain_ports_omitted": self.uncertain_omitted,
            "application_bytes_sent": 0,
        }


def _surface(value: object, addresses: tuple[str, ...], ports: tuple[int, ...]) -> Surface | None:
    if value is None:
        return None
    item = _object(value)
    if item.get("kind") != "passive-tcp-connect-survey" or _integer(item.get("application_bytes_sent")) != 0:
        raise ReportError("Unsupported surface or non-passive survey.")
    planned, observed = _integer(item.get("planned_pairs")), _integer(item.get("observed_pairs"))
    if observed > planned or planned != len(addresses) * len(ports):
        raise ReportError("Survey count or approved scope mismatch.")
    hosts = []
    for raw in _list(item.get("hosts"), MAX_HOSTS):
        host = _object(raw)
        address = str(canonical_ip(_text(host.get("address"), 64)))
        if address not in addresses or host.get("tcp_response") not in {"observed-or-middlebox", "unknown"}:
            raise ReportError("Invalid surface host.")
        counts = _object(host.get("counts"))
        normalized = tuple((state.value, _integer(counts.get(state.value))) for state in PortState)
        if sum(count for _, count in normalized) > len(ports):
            raise ReportError("Host state counts exceed approved ports.")
        hosts.append(SurfaceHost(address, str(host["tcp_response"]), normalized))
    if {host.address for host in hosts} != set(addresses) or len(hosts) != len(addresses):
        raise ReportError("Surface hosts do not match approved scope.")
    if sum(count for host in hosts for _, count in host.counts) != observed:
        raise ReportError("Observed pairs disagree with host counts.")
    records: list[tuple[PortObservation, ...]] = []
    seen: set[tuple[str, int]] = set()
    for key in ("open_ports", "uncertain_ports"):
        collected = []
        for raw in _list(item.get(key, []), MAX_SURFACE_PORTS):
            entry = _object(raw)
            service = entry.get("service")
            identity = None
            if service is not None:
                fields = _object(service)
                if fields.get("identity_verified") is not False:
                    raise ReportError("Passive identities cannot claim verified authenticity.")
                identity = ServiceIdentity(
                    _text(fields.get("protocol"), 48),
                    _text(fields["product"], 48) if fields.get("product") is not None else None,
                    _text(fields["advertised_version"], 64) if fields.get("advertised_version") is not None else None,
                    _text(fields["cpe_query"]) if fields.get("cpe_query") is not None else None,
                )
            record = PortObservation(
                _text(entry.get("address"), 64),
                validate_port(entry.get("port")),
                PortState(entry.get("state")),
                BannerState(entry.get("banner")),
                identity,
            )
            pair = record.address, record.port
            if record.address not in addresses or record.port not in ports or pair in seen:
                raise ReportError("Surface endpoint is duplicated or outside approved scope.")
            if (key == "open_ports" and record.state is not PortState.OPEN) or (
                key == "uncertain_ports" and record.state in {PortState.OPEN, PortState.REFUSED}
            ):
                raise ReportError("Surface state disagrees with its collection.")
            seen.add(pair)
            collected.append(record)
        records.append(tuple(collected))
    opened, uncertain = records
    open_omitted, uncertain_omitted = (
        _integer(item.get("open_ports_omitted", 0)),
        _integer(item.get("uncertain_ports_omitted", 0)),
    )
    totals = {state.value: sum(dict(host.counts)[state.value] for host in hosts) for state in PortState}
    if len(opened) + open_omitted != totals[PortState.OPEN.value] or len(uncertain) + uncertain_omitted != sum(
        count for state, count in totals.items() if state not in {PortState.OPEN.value, PortState.REFUSED.value}
    ):
        raise ReportError("Surface inventory and omitted counts disagree.")
    incomplete, failed = _boolean(item.get("incomplete")), _boolean(item.get("failed"))
    if observed < planned and not incomplete or failed and not incomplete:
        raise ReportError("Partial survey cannot claim complete coverage.")
    return Surface(
        planned, observed, incomplete, failed, tuple(hosts), opened, uncertain, open_omitted, uncertain_omitted
    )


@dataclass(frozen=True)
class ReportDocument:
    """Offline snapshot; imported scope declarations are not proof of authorization."""

    scan_id: str
    target: str
    mode: str
    started_at: datetime
    ended_at: datetime | None
    findings: tuple[Finding, ...]
    outcomes: tuple[CheckOutcome, ...]
    operations: tuple[tuple[str, int], ...]
    limits: tuple[tuple[str, object], ...]
    addresses: tuple[str, ...]
    ports: tuple[int, ...]
    surface: Surface | None
    purpose: str

    @classmethod
    def from_result(
        cls, result: ScanResult, purpose: str = "Engine-supplied result; applicability requires assessment."
    ) -> "ReportDocument":
        """Copy finished or partial engine data through the same strict export boundary."""
        return cls.from_mapping({**result.to_dict(), "purpose": purpose})

    @classmethod
    def from_mapping(cls, value: object) -> "ReportDocument":
        """Validate bounded result v1 input, recompute counts and discard unknown metadata."""
        try:
            item = _object(value)
            if item.get("schema") != "vulnscanner.result.v1":
                raise ReportError("Unsupported source-result schema.")
            scan_id = str(UUID(_text(item.get("scan_id"), 36)))
            mode = ScanMode(item.get("mode"))
            target = Target(mode, _text(item.get("target"), 4096)).display
            started = _time(item.get("started_at"))
            ended = _time(item["ended_at"]) if item.get("ended_at") is not None else None
            if ended is not None and ended < started:
                raise ReportError("Completion precedes scan start.")
            findings = tuple(_finding(raw) for raw in _list(item.get("findings"), MAX_FINDINGS))
            findings = tuple(
                sorted(
                    findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.rule_id, f.evidence.endpoint, f.title)
                )
            )
            outcomes = tuple(
                sorted((_outcome(raw) for raw in _list(item.get("coverage"), MAX_CHECKS)), key=lambda o: o.check)
            )
            if len({outcome.check for outcome in outcomes}) != len(outcomes):
                raise ReportError("Duplicate check coverage.")
            scope = _object(item.get("approved_scope", {"addresses": [], "ports": []}))
            addresses = tuple(str(canonical_ip(_text(raw, 64))) for raw in _list(scope.get("addresses"), MAX_HOSTS))
            ports = tuple(validate_port(raw) for raw in _list(scope.get("ports"), MAX_PORTS))
            if len(set(addresses)) != len(addresses) or len(set(ports)) != len(ports):
                raise ReportError("Duplicate scope entries.")
            operations = _object(item.get("operations", {}))
            operation_counts = tuple((name, _integer(operations.get(name, 0))) for name in ("HTTP", "TCP", "TLS"))
            if sum(count for _, count in operation_counts) > MAX_OPERATIONS:
                raise ReportError("Total operation count exceeds engine maximum.")
            limits = _object(item.get("limits", {}))
            allowed = ScanConfig().public_limits()
            retained = {name: value for name, value in limits.items() if name in allowed}
            ScanConfig(**retained)
            surface = _surface(item.get("attack_surface"), addresses, ports)
            if mode is ScanMode.WEB and surface is not None:
                raise ReportError("A web result cannot include a network survey.")
            purpose = _text(item.get("purpose", "Operator-supplied result; provenance is not verified."))
            return cls(
                scan_id,
                target,
                mode.value,
                started,
                ended,
                findings,
                outcomes,
                operation_counts,
                tuple(sorted(retained.items())),
                addresses,
                tuple(sorted(ports)),
                surface,
                purpose,
            )
        except ReportError:
            raise
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            raise ReportError("Source result has an invalid field; no report was produced.") from exc

    @property
    def counts(self) -> dict[str, int]:
        """Recompute severity counts; imported summary numbers are never trusted."""
        return {severity.value: sum(f.severity is severity for f in self.findings) for severity in SEVERITY_ORDER}

    @property
    def coverage_counts(self) -> dict[str, int]:
        """Count all outcomes without turning unknown coverage into a clean result."""
        return {status.value: sum(o.status is status for o in self.outcomes) for status in CheckStatus}

    @property
    def complete(self) -> bool:
        """Require completion time, selected coverage and a complete network survey."""
        return (
            self.ended_at is not None
            and bool(self.outcomes)
            and all(o.status is CheckStatus.COMPLETE for o in self.outcomes)
            and (self.surface is None or not self.surface.incomplete)
        )

    @property
    def highest_severity(self) -> str:
        """Describe recorded severity without inventing an overall business-risk rating."""
        return self.findings[0].severity.value.capitalize() if self.findings else "None recorded"

    @property
    def summary(self) -> str:
        """Provide a factual executive summary with confidence and coverage limits."""
        potential = sum(f.confidence is Confidence.POTENTIAL for f in self.findings)
        completed = self.coverage_counts["complete"]
        return f"{len(self.findings)} findings recorded; highest reported severity: {self.highest_severity}. {completed} of {len(self.outcomes)} selected checks completed. {potential} findings need manual verification. Automated observations do not establish exploitability, compliance or complete security."

    def metadata(self) -> dict[str, object]:
        """Export recognized scan/coverage metadata for SARIF and other consumers."""
        return {
            "scanId": self.scan_id,
            "target": self.target,
            "mode": self.mode,
            "purpose": self.purpose,
            "startedAt": self.started_at.isoformat(),
            "endedAt": self.ended_at.isoformat() if self.ended_at else None,
            "coverageComplete": self.complete,
            "highestReportedSeverity": self.highest_severity,
            "severityCounts": self.counts,
            "coverageCounts": self.coverage_counts,
            "coverage": [{"check": o.check, "status": o.status.value, "reason": o.reason} for o in self.outcomes],
            "operations": dict(self.operations),
            "limits": dict(self.limits),
            "approvedScope": {"addresses": list(self.addresses), "ports": list(self.ports)},
            "attackSurface": self.surface.to_dict() if self.surface else None,
        }
