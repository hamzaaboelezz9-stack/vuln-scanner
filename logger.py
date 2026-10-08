"""Scanner-only logging; no HTTP debug logs, tracebacks or raw target exception strings."""

import logging

from rich.console import Console
from rich.logging import RichHandler


def configure_logging(console: Console, verbose: bool = False, quiet: bool = False) -> None:
    """Configure only scanner loggers with literal Rich text and bounded authored diagnostics."""
    logger = logging.getLogger("scanner")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.WARNING if quiet else logging.DEBUG if verbose else logging.INFO)
    handler = RichHandler(
        console=console, markup=False, rich_tracebacks=False, show_time=False, show_path=False, enable_link_path=False
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
