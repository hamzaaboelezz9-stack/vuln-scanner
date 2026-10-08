"""GitHub-friendly Markdown with untrusted text escaped outside fixed code blocks."""

import html
import re

from scanner.reporting.model import ReportDocument

MARKDOWN_PUNCTUATION = re.compile(r"([\\`*_{}\[\]()#+.!|>~-])")


def escape_markdown(value: str) -> str:
    """Neutralize raw HTML, table/fence syntax and mention notifications in prose."""
    escaped = MARKDOWN_PUNCTUATION.sub(r"\\\1", html.escape(value, quote=True))
    return escaped.replace("@", "&#64;").replace("\n", " ").replace("\t", " ")


def code_block(value: str) -> str:
    """Choose a fence longer than any attacker-controlled backtick run."""
    longest = max((len(match.group()) for match in re.finditer(r"`+", value)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{value}\n{fence}"


def render_markdown(document: ReportDocument) -> str:
    """Render full findings, explicit coverage and bounded surface into a shareable file."""
    md = escape_markdown
    lines = [
        "# VulnScanner security assessment",
        "",
        f"**Target:** {md(document.target)}  ",
        f"**Scan ID:** {document.scan_id}  ",
        f"**Mode:** {document.mode} | **Coverage:** {'Complete' if document.complete else 'Partial / unfinished'}",
        "",
        "## Executive summary",
        "",
        md(document.summary),
        "",
        f"**Provenance:** {md(document.purpose)}",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    lines.extend(f"| {severity.capitalize()} | {count} |" for severity, count in document.counts.items())
    lines.extend(
        [
            "",
            "## Scope and coverage",
            "",
            "Scope is declared in the source result; this report does not independently verify permission.",
            "",
            f"**Started (UTC):** {document.started_at.isoformat()}  ",
            f"**Ended (UTC):** {document.ended_at.isoformat() if document.ended_at else 'Not recorded'}",
            "",
            "| Check | Outcome | Explanation |",
            "| --- | --- | --- |",
        ]
    )
    lines.extend(
        f"| {md(o.check)} | {o.status.value} | {md(o.reason) or 'Completed selected check'} |"
        for o in document.outcomes
    )
    if not document.outcomes:
        lines.append("| None recorded | unknown | No check coverage was supplied |")
    lines.extend(
        [
            "",
            "**Declared approved addresses:**",
            "",
            code_block("\n".join(document.addresses) or "None recorded"),
            "",
            "**Declared approved ports:**",
            "",
            code_block(", ".join(str(port) for port in document.ports) or "None recorded"),
            "",
            "**Operations:** " + ", ".join(f"{kind}={count}" for kind, count in document.operations),
            "",
        ]
    )
    if document.surface:
        surface = document.surface
        lines.extend(
            [
                "## Attack surface",
                "",
                f"{surface.observed} of {surface.planned} host/port pairs observed. Identities are advertised and unverified.",
                "",
                f"Collection incomplete: {surface.incomplete}. Collection failed: {surface.failed}.",
                "",
                "| Endpoint | Socket state | Advertised protocol/product/version | Greeting status |",
                "| --- | --- | --- | --- |",
            ]
        )
        for port in (*surface.opened, *surface.uncertain):
            identity = (
                " / ".join(filter(None, (port.service.protocol, port.service.product, port.service.version)))
                if port.service
                else "Unknown"
            )
            lines.append(f"| {md(port.endpoint)} | {port.state.value} | {md(identity)} | {port.banner_state.value} |")
        lines.extend(
            [
                "",
                f"Omitted inventory records: {surface.open_omitted} open, {surface.uncertain_omitted} uncertain. Timeouts do not prove a closed port or an absent host.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "## Attack surface",
                "",
                "Network inventory was not supplied. Web coverage is limited to the recorded target and selected checks.",
                "",
            ]
        )
    lines.extend(["## Findings", ""])
    if not document.findings:
        lines.extend(["No findings recorded. This does not establish that the application is secure.", ""])
    for index, finding in enumerate(document.findings, 1):
        score = (
            f"{finding.cvss.score:.1f} | {finding.cvss.vector}"
            if finding.cvss
            else "Not scored — impact needs verification"
        )
        evidence = (
            f"{finding.evidence.method} {finding.evidence.endpoint}\nHTTP status: {finding.evidence.status_code if finding.evidence.status_code else 'Not applicable / unavailable'}\n"
            + "\n".join(finding.evidence.observations)
        )
        lines.extend(
            [
                f"### FINDING-{index:03d}: {md(finding.title)}",
                "",
                f"**Rule:** {md(finding.rule_id)}  ",
                f"**Severity:** {finding.severity.value.capitalize()} | **Confidence:** {finding.confidence.value}  ",
                f"**CVSS v3.1:** {md(score)}",
                "",
                "**Description:**",
                "",
                md(finding.description),
                "",
                "**Evidence:**",
                "",
                code_block(evidence),
                "",
                "**Remediation:**",
                "",
                md(finding.remediation),
                "",
                "**References:**",
                "",
            ]
        )
        lines.extend(f"- [Reference {i}]({url})" for i, url in enumerate(finding.references, 1))
        if not finding.references:
            lines.append("No reference supplied.")
        lines.append("")
    lines.extend(
        [
            "## Recommended next steps",
            "",
            "1. Prioritize confirmed high-impact findings and verify potential issues before remediation decisions.",
            "2. Resolve skipped, inconclusive and failed checks; rerun within the same authorized scope.",
            "3. Retest fixes and supplement automated checks with manual application assessment.",
            "",
            "Reports contain assessment metadata. Review and redact before publishing or sending to an issue tracker.",
            "",
        ]
    )
    return "\n".join(lines)
