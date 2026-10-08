"""SARIF 2.1.0 export with explicit scanner-specific evidence and coverage properties."""

import hashlib
import json
from urllib.parse import quote, urlsplit

from scanner import __version__
from scanner.core.finding import Finding, Severity
from scanner.reporting.model import ReportDocument

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "note",
}


def _result(finding: Finding, index: int) -> dict[str, object]:
    # Fingerprints use stable issue/endpoint data, never volatile times, raw bodies or secrets.
    identity = "\0".join((finding.rule_id, finding.evidence.method, finding.evidence.endpoint, finding.title))
    properties: dict[str, object] = {
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "evidence": finding.to_dict()["evidence"],
        "remediation": finding.remediation,
        "references": list(finding.references),
        "cvss": finding.to_dict()["cvss"],
    }
    result: dict[str, object] = {
        "ruleId": finding.rule_id,
        "ruleIndex": index,
        "level": LEVELS[finding.severity],
        "kind": "informational" if finding.severity is Severity.INFO else "fail",
        "message": {"text": f"{finding.title}: {finding.description}"},
        "partialFingerprints": {"vulnscannerIssue/v1": hashlib.sha256(identity.encode("utf-8")).hexdigest()},
        "properties": properties,
    }
    # Dynamic endpoints have no source-code line numbers. Do not invent file/region locations.
    try:
        parsed = urlsplit(finding.evidence.endpoint)
    except ValueError:
        parsed = None
    if parsed and parsed.scheme in {"http", "https", "tcp", "tls"} and parsed.hostname:
        uri = quote(finding.evidence.endpoint, safe=":/?@#[]%&=+,$;!*'()-._~")
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
    return result


def to_sarif(document: ReportDocument) -> dict[str, object]:
    """Build valid SARIF plus extension properties; null CVSS remains unscored."""
    identifiers = sorted({finding.rule_id for finding in document.findings})
    indices = {name: index for index, name in enumerate(identifiers)}
    rules = []
    for name in identifiers:
        example = next(finding for finding in document.findings if finding.rule_id == name)
        rules.append({"id": name, "shortDescription": {"text": example.title}, "help": {"text": example.remediation}})
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "VulnScanner", "version": __version__, "rules": rules}},
                "results": [_result(finding, indices[finding.rule_id]) for finding in document.findings],
                "properties": {"vulnscanner": document.metadata()},
            }
        ],
    }


def render_json(document: ReportDocument) -> str:
    """Return deterministic UTF-8-ready SARIF; the schema URI is never fetched at runtime."""
    return json.dumps(to_sarif(document), indent=2, ensure_ascii=False, allow_nan=False) + "\n"
