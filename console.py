"""Rich terminal reporting; every target-controlled field is rendered as literal Text."""

from contextlib import contextmanager
from typing import Callable, Iterator

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from scanner.core.result import CheckOutcome
from scanner.reporting.model import ReportDocument

SEVERITY_STYLES = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "blue"}
ProgressCallback = Callable[[CheckOutcome, int, int], None]


class ConsoleReporter:
    """Present a consistent final summary plus a progress callback for the existing engine."""

    def __init__(self, console: Console | None = None) -> None:
        """Accept an injectable console for capture, no-color output and deterministic tests."""
        self.console = console or Console(markup=False, highlight=False)

    def render(self, document: ReportDocument, quiet: bool = False, verbose: bool = False) -> None:
        """Print findings in severity order; verbose mode adds evidence, never raw responses."""
        if not quiet:
            self.console.print(
                Panel(
                    Text(
                        f"{document.target}\n{document.summary}\nCoverage: {'complete' if document.complete else 'partial / unfinished'}\n{document.purpose}"
                    ),
                    title=Text("VulnScanner assessment"),
                    border_style="cyan",
                )
            )
            summary = Table(title=Text("Recorded findings"))
            summary.add_column("Severity")
            summary.add_column("Count", justify="right")
            for severity, count in document.counts.items():
                summary.add_row(Text(severity.capitalize(), style=SEVERITY_STYLES[severity]), Text(str(count)))
            self.console.print(summary)
            coverage = Table(title=Text("Check coverage"))
            for title in ("Check", "Outcome", "Explanation"):
                coverage.add_column(title)
            for outcome in document.outcomes:
                coverage.add_row(
                    Text(outcome.check), Text(outcome.status.value), Text(outcome.reason or "Completed selected check")
                )
            self.console.print(coverage)
            self.console.print(
                Text(
                    f"Scan ID: {document.scan_id}\nOperations: "
                    + ", ".join(f"{kind}={count}" for kind, count in document.operations)
                )
            )
        findings = Table(title=None if quiet else Text("Findings"), show_lines=True)
        compact = self.console.width < 110
        columns = (
            ("ID", "Severity", "Finding / confidence / endpoint", "CVSS")
            if compact
            else ("ID", "Severity", "Confidence", "Finding", "Endpoint", "CVSS")
        )
        for title in columns:
            findings.add_column(title)
        for index, finding in enumerate(document.findings, 1):
            identity = Text(f"{index:03d}")
            severity = Text(finding.severity.value.capitalize(), style=SEVERITY_STYLES[finding.severity.value])
            score = Text(f"{finding.cvss.score:.1f}" if finding.cvss else "Not scored")
            if compact:
                detail = Text(finding.title)
                detail.append(f"\n{finding.confidence.value}\n{finding.evidence.endpoint}", style="dim")
                findings.add_row(identity, severity, detail, score)
            else:
                findings.add_row(
                    identity,
                    severity,
                    Text(finding.confidence.value),
                    Text(finding.title),
                    Text(finding.evidence.endpoint),
                    score,
                )
        if document.findings or not quiet:
            self.console.print(findings)
        if verbose:
            for index, finding in enumerate(document.findings, 1):
                self.console.print(
                    Panel(
                        Text(
                            f"{finding.description}\n\n{finding.evidence.method} {finding.evidence.endpoint}\n"
                            + "\n".join(finding.evidence.observations)
                            + f"\n\nRemediation: {finding.remediation}"
                        ),
                        title=Text(f"FINDING-{index:03d}"),
                    )
                )

    @contextmanager
    def progress(self, enabled: bool = True) -> Iterator[ProgressCallback]:
        """Yield a callback counting settled checks, not implying every settled check passed."""
        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
            disable=not enabled or not self.console.is_terminal,
        )
        task = progress.add_task("Selected checks settled", total=None)

        def update(outcome: CheckOutcome, completed: int, total: int) -> None:
            """Update settled-check counts without placing source text in progress markup."""
            # No target/exception text enters the progress description or markup parser.
            progress.update(task, completed=completed, total=total)

        with progress:
            yield update
