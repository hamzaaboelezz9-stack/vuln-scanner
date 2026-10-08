"""Exports never overwrite local files or follow symlinks, and preserve complete content."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from scanner.reporting.export import export_report
from scanner.reporting.io import write_reports
from scanner.reporting.model import ReportError
from tests.report_support import report_document, report_result


def test_all_exports_are_new_only_complete_and_private(tmp_path: Path) -> None:
    """One validated snapshot produces all formats with owner-only POSIX file permissions."""
    outputs = export_report(report_document(), tmp_path / "reports/report.v1", "all")
    assert [path.name for path in outputs] == ["report.v1.html", "report.v1.json", "report.v1.md"]
    for path in outputs:
        assert path.stat().st_nlink == 1 and stat.S_IMODE(path.stat().st_mode) == 0o600
        assert "Literal fixture" in path.read_text()
    assert stat.S_IMODE((tmp_path / "reports").stat().st_mode) == 0o700
    with pytest.raises(ReportError):
        export_report(report_document(), tmp_path / "reports/report.v1", "all")
    assert not list((tmp_path / "reports").glob(".vulnscanner-report-*"))


def test_existing_file_and_symlink_are_never_overwritten(tmp_path: Path) -> None:
    """A report name collision cannot truncate another local file through any link."""
    victim = tmp_path / "private.txt"
    victim.write_text("operator-owned-secret")
    link = tmp_path / "report.html"
    link.symlink_to(victim)
    for destination in (victim, link):
        with pytest.raises(ReportError):
            export_report(report_document(), destination)
    linked_directory = tmp_path / "linked-directory"
    linked_directory.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ReportError):
        export_report(report_document(), linked_directory / "new-report.html")
    assert victim.read_text() == "operator-owned-secret" and link.is_symlink()


def test_second_publication_failure_rolls_back_only_own_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A late link failure does not leave a deceptively complete multi-format export."""
    original = os.link
    calls = [0]

    def fail_second(source: Path, destination: Path) -> None:
        calls[0] += 1
        if calls[0] == 2:
            raise OSError("fictional link failure")
        original(source, destination)

    monkeypatch.setattr(os, "link", fail_second)
    with pytest.raises(ReportError):
        export_report(report_document(), tmp_path / "demo", "all")
    assert not list(tmp_path.iterdir())


def test_commit_time_collision_is_atomic_and_preserves_other_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A concurrent writer appearing after preflight wins; its file is not followed/changed."""
    original = os.link

    def race(source: Path, destination: Path) -> None:
        destination.write_text("other-writer")
        original(source, destination)

    monkeypatch.setattr(os, "link", race)
    output = tmp_path / "report.html"
    with pytest.raises(ReportError):
        export_report(report_document(), output)
    assert output.read_text() == "other-writer"
    assert not list(tmp_path.glob(".vulnscanner-report-*"))


def test_bad_format_and_bad_unicode_create_no_files(tmp_path: Path) -> None:
    """Rendering/input encoding errors cannot publish incomplete local files."""
    with pytest.raises(ReportError):
        export_report(report_document(), tmp_path / "file", "exe")
    with pytest.raises(ReportError):
        write_reports({tmp_path / "file": "\ud800"})
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("incomplete,expected", [(False, 0), (True, 2)])
def test_report_cli_exports_from_stdin_with_coverage_exit_status(
    tmp_path: Path, incomplete: bool, expected: int
) -> None:
    """Offline stdin/report export retains outcome codes without asking for scan permission."""
    raw = report_result().to_dict()
    if incomplete:
        raw["coverage"][0] = {"check": "headers", "status": "failed", "reason": "Fictional failure."}
    executed = subprocess.run(
        [
            sys.executable,
            "-m",
            "scanner.reporting.cli",
            "-",
            "--output",
            str(tmp_path / "result"),
            "--format",
            "all",
            "--no-color",
        ],
        input=json.dumps(raw),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert executed.returncode == expected and "permission" not in executed.stderr
    assert "Literal" in executed.stdout and "fixture" in executed.stdout and "\x1b" not in executed.stdout
    assert "Literal fixture" in (tmp_path / "result.json").read_text()
    assert len(list(tmp_path.iterdir())) == 3


def test_report_cli_invalid_input_is_safe_error_and_no_output(tmp_path: Path) -> None:
    """Invalid input yields a categorized message, not parser details or a raw secret."""
    executed = subprocess.run(
        [sys.executable, "-m", "scanner.reporting.cli", "-", "--output", str(tmp_path / "result.html")],
        input="private-secret not json",
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert executed.returncode == 1 and "private-secret" not in executed.stderr
    assert not executed.stdout and not list(tmp_path.iterdir())
