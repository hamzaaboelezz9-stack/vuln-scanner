"""Report content remains inert in HTML, terminal, Markdown and SARIF output."""

import base64
import hashlib
import io
import json
from html.parser import HTMLParser
from pathlib import Path

import pytest
from rich.console import Console
from rich.progress import Progress

from scanner.checks.base import BaseCheck, CheckContext, CheckInfo, CheckRegistry
from scanner.core.config import ScanConfig
from scanner.core.engine import ScanEngine
from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.result import CheckStatus
from scanner.core.target import ScanMode, Target
from scanner.reporting.console import ConsoleReporter
from scanner.reporting.html import render_html
from scanner.reporting.io import load_result
from scanner.reporting.json_export import render_json, to_sarif
from scanner.reporting.markdown import code_block, render_markdown
from scanner.reporting.model import ReportDocument
from scanner.safety.authorization import ScopeGate
from scanner.safety.state import AuthorizationStore
from tests.report_support import report_document, report_result


class ReportParser(HTMLParser):
    """Inspect actual browser-facing elements, links and style/CSP bytes."""

    def __init__(self) -> None:
        """Capture security-sensitive elements without executing anything."""
        super().__init__()
        self.elements: list[tuple[str, dict[str, str | None]]] = []
        self.in_style = False
        self.css = ""
        self.csp = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Collect tags/attributes and the effective unescaped CSP attribute."""
        attributes = dict(attrs)
        self.elements.append((tag, attributes))
        if tag == "style":
            self.in_style = True
        if tag == "meta" and attributes.get("http-equiv") == "Content-Security-Policy":
            self.csp = attributes.get("content") or ""

    def handle_endtag(self, tag: str) -> None:
        """Stop collecting authored CSS at the closing style tag."""
        if tag == "style":
            self.in_style = False

    def handle_data(self, data: str) -> None:
        """Retain exact CSS text for hash validation."""
        if self.in_style:
            self.css += data


def test_html_autoescape_csp_and_no_active_or_remote_assets() -> None:
    """Attacker text cannot introduce tags, handlers, style or network fetches."""
    payload = '</style><script>alert(1)</script><img src="https://evil.invalid/x" onerror="boom"> {{ 7*7 }}'
    report = render_html(report_document(payload))
    parser = ReportParser()
    parser.feed(report)
    assert not any(tag in {"script", "img", "iframe", "object", "link", "form"} for tag, _ in parser.elements)
    assert not any(key.startswith("on") or key == "style" for _, attrs in parser.elements for key in attrs)
    assert "&lt;script&gt;" in report and "{{ 7*7 }}" in report
    assert "script-src 'none'" in parser.csp and "connect-src 'none'" in parser.csp
    assert "unsafe-inline" not in parser.csp and "unsafe-eval" not in parser.csp
    digest = base64.b64encode(hashlib.sha256(parser.css.encode()).digest()).decode()
    assert f"style-src 'sha256-{digest}'" in parser.csp
    for tag, attrs in parser.elements:
        if tag == "a" and (attrs.get("href") or "").startswith("https://"):
            assert attrs.get("rel") == "noopener noreferrer"
            assert attrs.get("target") == "_blank"
    assert "never-publish" not in report


def test_terminal_markup_and_osc_are_literal_or_removed() -> None:
    """Target strings never reach Rich's markup/ANSI parsers."""
    text = "[bold red]literal[/bold red] \x1b]8;;https://evil.invalid\x07link\x1b]8;;\x07\u202e"
    output = io.StringIO()
    reporter = ConsoleReporter(Console(file=output, width=160, color_system=None, markup=True, highlight=True))
    reporter.render(report_document(text), verbose=True)
    rendered = output.getvalue()
    assert "[bold red]literal[/bold red]" in rendered
    assert "\x1b" not in rendered and "\x07" not in rendered and "\u202e" not in rendered
    assert "never-publish" not in rendered


def test_markdown_html_mentions_pipes_and_fence_injection_are_neutralized() -> None:
    """Code observations cannot break their fence or inject issue mentions/prose HTML."""
    text = "</pre><script>evil()</script>\n```\n# forged heading | @everyone [click](javascript:evil)"
    document = report_document(text)
    markdown = render_markdown(document)
    assert "<script>" not in markdown.split("**Evidence:**")[0]
    assert "&#64;everyone" in markdown and "\\|" in markdown
    assert "````text\n" in markdown
    assert code_block("````\nattack\n````").startswith("`````text\n")
    assert "](javascript:" not in markdown.split("**Evidence:**")[0]
    assert "never-publish" not in markdown


@pytest.mark.parametrize(
    "severity,level,kind",
    [
        (Severity.CRITICAL, "error", "fail"),
        (Severity.HIGH, "error", "fail"),
        (Severity.MEDIUM, "warning", "fail"),
        (Severity.LOW, "warning", "fail"),
        (Severity.INFO, "note", "informational"),
    ],
)
def test_sarif_levels_rule_indices_confidence_and_cvss(severity: Severity, level: str, kind: str) -> None:
    """Standard SARIF fields and scanner extensions preserve the original certainty."""
    raw = report_result().to_dict()
    raw["findings"][0]["severity"] = severity.value
    sarif = to_sarif(ReportDocument.from_mapping(raw))
    run = sarif["runs"][0]
    result = run["results"][0]
    assert sarif["version"] == "2.1.0"
    assert result["level"] == level and result["kind"] == kind
    assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
    assert result["properties"]["confidence"] == Confidence.POTENTIAL.value
    assert result["properties"]["cvss"] is None
    assert "never-publish" not in json.dumps(sarif)
    assert "region" not in result["locations"][0]["physicalLocation"]


def test_sarif_fingerprints_ignore_timing_and_multiple_same_rule_findings() -> None:
    """Stable issue identity survives distinct scan IDs and completion timestamps."""
    raw = report_result().to_dict()
    original = to_sarif(ReportDocument.from_mapping(raw))["runs"][0]["results"][0]
    raw["scan_id"] = "489f79f1-9b31-4fb4-b16b-d95a41dde4c9"
    raw["ended_at"] = "2026-10-07T13:00:00Z"
    raw["findings"] *= 2
    run = to_sarif(ReportDocument.from_mapping(raw))["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1 and len(run["results"]) == 2
    assert run["results"][0]["partialFingerprints"] == original["partialFingerprints"]


def test_malformed_non_http_endpoint_remains_literal_not_a_location() -> None:
    """An unparseable display endpoint cannot crash JSON or manufacture a valid URI."""
    raw = report_result().to_dict()
    raw["findings"][0]["evidence"]["endpoint"] = "tcp://[invalid-ipv6"
    result = to_sarif(ReportDocument.from_mapping(raw))["runs"][0]["results"][0]
    assert "locations" not in result


def test_null_cvss_and_incomplete_checks_visible_in_all_formats() -> None:
    """Incomplete measured samples retain their skipped/inconclusive reasons everywhere."""
    document = load_result(Path(__file__).parents[1] / "docs/NETWORK_SAMPLE.json")
    for renderer in (render_html, render_markdown, render_json):
        text = renderer(document)
        assert "skipped" in text and "cves" in text
        assert "Not scored" in text or '"cvss": null' in text
    assert to_sarif(document)["runs"][0]["properties"]["vulnscanner"]["coverageComplete"] is False


def test_report_rendering_does_not_resolve_or_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    """No exporter can trigger lookup, reference fetch or remote asset loading in Python."""
    import socket

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Offline render attempted network access.")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    document = report_document()
    for renderer in (render_html, render_markdown, render_json):
        assert renderer(document)


def test_quiet_console_contains_only_findings_and_empty_quiet_is_empty() -> None:
    """Quiet presentation does not alter the underlying finding/coverage record."""
    stream = io.StringIO()
    reporter = ConsoleReporter(Console(file=stream, width=140, color_system=None))
    reporter.render(report_document(), quiet=True)
    assert "Literal fixture" in stream.getvalue() and "Scan ID" not in stream.getvalue()
    result = report_result()
    result.findings.clear()
    stream.truncate(0)
    stream.seek(0)
    reporter.render(ReportDocument.from_result(result), quiet=True)
    assert stream.getvalue() == ""


def test_progress_callback_integrates_with_engine_and_settles_failed_checks(
    state: AuthorizationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A settled failed check advances progress while coverage remains explicitly failed."""
    registry = CheckRegistry()

    @registry.register(CheckInfo("good", ScanMode.WEB, "Fixture no-I/O check", 1))
    class Good(BaseCheck):
        """Return no findings without doing any target IO."""

        def run(self, context: CheckContext) -> list[Finding]:
            """Exercise the engine/report callback contract."""
            return []

    @registry.register(CheckInfo("bad", ScanMode.WEB, "Fixture failure check", 1))
    class Bad(BaseCheck):
        """Fail safely without doing target IO."""

        def run(self, context: CheckContext) -> list[Finding]:
            """Trigger engine-owned explicit failed coverage."""
            raise ValueError("fictional test failure")

    updates: list[tuple[object, object]] = []
    original = Progress.update

    def record(self: Progress, *args: object, **kwargs: object) -> None:
        updates.append((kwargs.get("completed"), kwargs.get("total")))
        original(self, *args, **kwargs)

    monkeypatch.setattr(Progress, "update", record)
    reporter = ConsoleReporter(Console(file=io.StringIO(), color_system=None))
    with reporter.progress(enabled=False) as callback:
        result = ScanEngine(ScopeGate(state), ScanConfig(), registry).run(
            Target.web("http://localhost:3000"), progress=callback
        )
    assert updates == [(1, 2), (2, 2)]
    assert any(outcome.status is CheckStatus.FAILED for outcome in result.outcomes)
    assert not ReportDocument.from_result(result).complete
