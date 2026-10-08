"""Bounded local result loading and new-only report files with restrictive permissions."""

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import BinaryIO, Mapping

from scanner.reporting.model import ReportDocument, ReportError

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 200_000
MAX_REPORT_FILES = 4  # Three reports plus one optional native result snapshot.


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReportError("Duplicate JSON keys are not accepted.")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ReportError("Non-finite JSON numbers are not accepted.")


def parse_json(raw: bytes) -> object:
    """Parse bounded UTF-8 JSON without duplicate keys, non-finite numbers or deep trees."""
    if not isinstance(raw, bytes) or len(raw) > MAX_INPUT_BYTES:
        raise ReportError("Input must be binary JSON within the 16 MiB limit.")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        stack = [(value, 0)]
        visited = 0
        while stack:
            node, depth = stack.pop()
            visited += 1
            if depth > MAX_JSON_DEPTH or visited > MAX_JSON_NODES:
                raise ReportError("Source-result structure exceeds its bounds.")
            if isinstance(node, dict):
                stack.extend((child, depth + 1) for child in node.values())
            elif isinstance(node, list):
                stack.extend((child, depth + 1) for child in node)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReportError("Input is not a supported UTF-8 JSON result.") from exc


def load_stream(stream: BinaryIO) -> ReportDocument:
    """Read one bounded JSON document and validate the recognized source-result fields."""
    return ReportDocument.from_mapping(parse_json(stream.read(MAX_INPUT_BYTES + 1)))


def load_result(path: Path) -> ReportDocument:
    """Read a regular local file without following a symlink or waiting on a device/FIFO."""
    descriptor = None
    try:
        # O_NONBLOCK prevents a malicious FIFO from blocking before fstat can reject it.
        if path.is_symlink():
            raise ReportError("Source result must not be a symbolic link.")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_INPUT_BYTES:
            raise ReportError("Source result must be a bounded regular file.")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            return load_stream(stream)
    except OSError as exc:
        raise ReportError("Source result could not be read.") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def write_reports(reports: Mapping[Path, str]) -> tuple[Path, ...]:
    """Publish complete files using new-only hard links; never overwrite existing paths.

    The destination directory must be controlled by the operator. On POSIX,
    temporary/output files are mode 0600 and newly created directories are 0700.
    A multi-file publication is best-effort rollback, not a filesystem transaction.
    """
    if not reports or len(reports) > MAX_REPORT_FILES:
        raise ReportError("Export requires one to four output files.")
    staged: list[tuple[Path, Path]] = []
    committed: list[tuple[Path, int, int]] = []
    try:
        encoded = []
        for requested, content in reports.items():
            if not isinstance(requested, Path) or not requested.name or requested.name in {".", ".."}:
                raise ReportError("Invalid output path.")
            path = requested.absolute()
            if any(parent.is_symlink() for parent in (path.parent, *path.parents)) or path.is_symlink():
                raise ReportError("Output paths must not traverse symbolic links.")
            if path.exists():
                raise ReportError("An output path already exists; choose a new name.")
            data = content.encode("utf-8")
            if len(data) > MAX_OUTPUT_BYTES:
                raise ReportError("Rendered report exceeds the 32 MiB output limit.")
            encoded.append((path, data))
        for path, data in encoded:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor, name = tempfile.mkstemp(prefix=".vulnscanner-report-", dir=path.parent)
            temporary = Path(name)
            staged.append((path, temporary))
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        for path, temporary in staged:
            # Linking fails atomically if any file/symlink appeared since preflight.
            metadata = temporary.stat()
            os.link(temporary, path)
            committed.append((path, metadata.st_dev, metadata.st_ino))
        return tuple(path for path, _ in staged)
    except (OSError, UnicodeError) as exc:
        raise ReportError("Report publication failed; existing files were not overwritten.") from exc
    finally:
        # On failure remove only our exact inode, never a concurrently replaced path.
        success = len(committed) == len(reports)
        if not success:
            for path, device, inode in committed:
                try:
                    metadata = path.lstat()
                    if metadata.st_dev == device and metadata.st_ino == inode:
                        path.unlink()
                except OSError:
                    pass  # A failed rollback cannot justify touching a different local file.
        for _, temporary in staged:
            try:
                temporary.unlink()
            except OSError:
                pass  # Best-effort cleanup; residual staged files retain owner-only permissions.
