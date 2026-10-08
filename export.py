"""One export dispatcher keeps every file based on the same validated snapshot."""

from pathlib import Path

from scanner.reporting.html import render_html
from scanner.reporting.io import write_reports
from scanner.reporting.json_export import render_json
from scanner.reporting.markdown import render_markdown
from scanner.reporting.model import ReportDocument, ReportError

FORMATS = {"html": render_html, "json": render_json, "md": render_markdown}


def render_reports(document: ReportDocument, output: Path, format_name: str = "html") -> dict[Path, str]:
    """Prepare one or three complete reports, allowing a CLI snapshot in the same publication."""
    if format_name not in {*FORMATS, "all"}:
        raise ReportError("Unknown report format.")
    if format_name == "all":
        # Treat output as an exact prefix: report.v1 -> report.v1.html/.json/.md.
        reports = {Path(str(output) + "." + name): render(document) for name, render in FORMATS.items()}
    else:
        reports = {output: FORMATS[format_name](document)}
    return reports


def export_report(document: ReportDocument, output: Path, format_name: str = "html") -> tuple[Path, ...]:
    """Export one named file or three files from an exact output prefix, without overwriting."""
    return write_reports(render_reports(document, output, format_name))
