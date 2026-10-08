"""Offline report-only CLI; loading/exporting a result performs no DNS or scan requests."""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.text import Text

from scanner.reporting.console import ConsoleReporter
from scanner.reporting.export import export_report
from scanner.reporting.io import load_result, load_stream
from scanner.reporting.model import ReportError


def main(argv: list[str] | None = None) -> int:
    """Read existing result v1 JSON and print/export it with explicit coverage exit status."""
    parser = argparse.ArgumentParser(description="Render an existing VulnScanner result offline. No scan is performed.")
    parser.add_argument("input", help="Result JSON path, or '-' for binary stdin")
    parser.add_argument("--output", type=Path, help="Output file; exact filename prefix with --format all")
    parser.add_argument("--format", choices=("html", "json", "md", "all"), default="html")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show minimal evidence and remediation in console")
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Console findings only; file exports remain complete"
    )
    parser.add_argument("--no-color", action="store_true", help="Disable terminal colors")
    args = parser.parse_args(argv)
    console = Console(markup=False, highlight=False, no_color=args.no_color)
    errors = Console(stderr=True, markup=False, highlight=False, no_color=args.no_color)
    try:
        document = load_stream(sys.stdin.buffer) if args.input == "-" else load_result(Path(args.input))
        # Write before presentation: failed input/export never prints an apparently finished report.
        paths = export_report(document, args.output, args.format) if args.output else ()
        ConsoleReporter(console).render(document, quiet=args.quiet, verbose=args.verbose)
        if not args.quiet:
            for path in paths:
                console.print(Text(f"Report saved: {path.name}"))
        return 0 if document.complete else 2
    except (ReportError, OSError) as exc:
        # ReportError messages are authored categories; OS paths/exception strings are not echoed.
        message = str(exc) if isinstance(exc, ReportError) else "Report could not be produced."
        errors.print(Text(message, style="red"))
        return 1
    except KeyboardInterrupt:
        errors.print(Text("Report generation interrupted.", style="yellow"))
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
