"""Render existing scan JSON; see --help for formats, paths and explicit coverage exit codes."""

from scanner.reporting.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
