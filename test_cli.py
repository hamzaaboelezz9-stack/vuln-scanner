"""Real CLI workflows and refusal paths; all listeners and exports are local fixtures."""

import io
import json
import os
from pathlib import Path

import pytest

from scanner.cli import builtin_registry, main
from scanner.reporting.io import load_result
from scanner.safety.state import AuthorizationStore
from tests.network_lab import greeting_lab
from tests.web_lab import Reply, serve_web_lab


def flags(state: AuthorizationStore) -> list[str]:
    """Use the isolated saved acknowledgment and literal uncolored terminal output."""
    return ["--state-dir", str(state.directory), "--no-color"]


def test_list_has_every_mode_and_no_authorization_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Listing checks needs neither a notice acknowledgment nor any network connection."""
    monkeypatch.setenv("VULNSCAN_STATE_DIR", str(tmp_path / "absent"))
    assert main(["checks", "--no-color"]) == 0
    output = capsys.readouterr().out
    assert "headers" in output and "cves" in output and "traversal" in output
    assert not (tmp_path / "absent").exists()
    registry = builtin_registry()
    assert len(registry.describe()) == 14
    assert registry is not builtin_registry()


@pytest.mark.parametrize("phrase", ["yes\n", "I have permission \n", "i have permission\n", "", "x" * 257])
def test_acknowledgment_rejects_inexact_or_unbounded_input(
    phrase: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A generic yes, whitespace folding or EOF cannot silently grant authorization."""
    monkeypatch.setattr("sys.stdin", io.StringIO(phrase))
    directory = tmp_path / "state"
    assert main(["acknowledge", "--state-dir", str(directory)]) == 1
    assert not (directory / "acknowledgment.json").exists()
    assert not (directory / "scans.log").exists()


def test_acknowledgment_env_and_saved_reuse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The container state override is honored, and an acknowledged run does not reread stdin."""
    directory = tmp_path / "state"
    monkeypatch.setenv("VULNSCAN_STATE_DIR", str(directory))
    monkeypatch.setattr("sys.stdin", io.StringIO("I have permission\r\n"))
    assert main(["acknowledge"]) == 0
    assert AuthorizationStore(directory).acknowledged()
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert main(["acknowledge"]) == 0


def test_actual_web_cli_four_private_outputs_and_scrubbed_audit(
    state: AuthorizationStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The real engine feeds all report formats and one replayable snapshot in one publication."""
    prefix, native = tmp_path / "reports" / "review", tmp_path / "reports" / "native.json"
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply()
        target = f"http://127.0.0.1:{lab.port}/?token=synthetic-cli-secret"
        result = main(
            [
                "web",
                target,
                "--checks",
                "headers,cookies",
                "--output",
                str(prefix),
                "--format",
                "all",
                "--result-json",
                str(native),
                "--threads",
                "2",
                *flags(state),
            ]
        )
        assert result == 0 and lab.requests
        assert {request.method for request in lab.requests} <= {"GET", "HEAD", "OPTIONS"}
    paths = [Path(str(prefix) + "." + suffix) for suffix in ("html", "json", "md")] + [native]
    for path in paths:
        assert path.is_file() and "synthetic-cli-secret" not in path.read_text()
        if os.name == "posix":
            assert path.stat().st_mode & 0o777 == 0o600
    snapshot = json.loads(native.read_text())
    assert snapshot["scanner_version"] == "0.6.0"
    assert load_result(native).complete
    sarif = json.loads(paths[1].read_text())
    assert sarif["version"] == "2.1.0"
    events = [json.loads(line) for line in (state.directory / "scans.log").read_text().splitlines()]
    assert events[-1]["scan_id"] == snapshot["scan_id"] and events[-1]["notice_acknowledged"]
    assert "?" not in events[-1]["target"]
    console = capsys.readouterr()
    assert "synthetic-cli-secret" not in console.out + console.err


def test_first_run_scan_prompts_and_saves_notice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A fresh scan asks for the exact phrase before its first target request."""
    directory = tmp_path / "new-state"
    monkeypatch.setattr("sys.stdin", io.StringIO("I have permission\n"))
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply()
        assert main(["web", f"http://127.0.0.1:{lab.port}", "--checks", "cookies", "--state-dir", str(directory)]) == 0
        assert lab.requests and AuthorizationStore(directory).acknowledged()


def test_network_cli_is_one_passive_connection_per_port(state: AuthorizationStore, tmp_path: Path) -> None:
    """The CLI reuses one shared TCP survey and never sends an authentication/service command."""
    native = tmp_path / "network.json"
    with greeting_lab() as lab:
        assert (
            main(
                [
                    "net",
                    "127.0.0.1",
                    "--ports",
                    str(lab.port),
                    "--checks",
                    "discovery,ports,services",
                    "--result-json",
                    str(native),
                    "--quiet",
                    *flags(state),
                ]
            )
            == 0
        )
        assert lab.connections == 1
        assert all(not item for item in lab.received)
    source = json.loads(native.read_text())
    assert source["operations"]["TCP"] == 1
    assert source["approved_scope"]["ports"] == [lab.port]
    assert "operator-selected exact ports" in source["purpose"]


def test_partial_coverage_still_exports_and_returns_two(state: AuthorizationStore, tmp_path: Path) -> None:
    """Skipped or inconclusive checks are kept in the report and never presented as clean coverage."""
    native = tmp_path / "partial.json"
    with serve_web_lab() as lab:
        assert (
            main(
                [
                    "web",
                    f"http://127.0.0.1:{lab.port}",
                    "--checks",
                    "traversal",
                    "--result-json",
                    str(native),
                    "--quiet",
                    *flags(state),
                ]
            )
            == 2
        )
    document = load_result(native)
    assert not document.complete and document.outcomes[0].status.value == "skipped"


@pytest.mark.parametrize(
    "extra",
    [
        ["--checks", "missing"],
        ["--checks", "ports"],
        ["--threads", "0"],
        ["--rate-limit", "11"],
        ["--checks", "headers,headers"],
        ["--checks", ""],
        ["--checks", "all,cookies"],
    ],
)
def test_invalid_scan_selection_limits_and_rate_fail_before_ack_or_traffic(
    extra: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLI preflight refuses malformed settings without consuming stdin or touching a target."""
    directory = tmp_path / "absent-state"
    stream = io.StringIO("I have permission\n")
    monkeypatch.setattr("sys.stdin", stream)
    with serve_web_lab() as lab:
        assert main(["web", f"http://127.0.0.1:{lab.port}", *extra, "--state-dir", str(directory)]) == 1
        assert not lab.requests
    assert stream.tell() == 0 and not directory.exists()


def test_aggressive_rate_requires_own_flag(state: AuthorizationStore) -> None:
    """The explicit rate flag permits pacing changes but does not grant public-target scope."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply()
        target = f"http://127.0.0.1:{lab.port}"
        assert (
            main(["web", target, "--checks", "cookies", "--rate-limit", "11", "--i-know-what-im-doing", *flags(state)])
            == 0
        )
    assert (
        main(
            [
                "web",
                "https://169.254.169.254",
                "--checks",
                "cookies",
                "--rate-limit",
                "11",
                "--i-have-permission",
                "--i-know-what-im-doing",
                *flags(state),
            ]
        )
        == 1
    )


@pytest.mark.parametrize("target", ["https://agency.gov", "http://169.254.169.254", "https://8.8.8.8"])
def test_public_permission_cannot_override_allowlist_and_hard_blocks(target: str, state: AuthorizationStore) -> None:
    """Even two permission flags cannot bypass mandatory scope or provider restrictions."""
    assert (
        main(["web", target, "--checks", "cookies", "--i-have-permission", "--i-know-what-im-doing", *flags(state)])
        == 1
    )
    event = json.loads((state.directory / "scans.log").read_text().splitlines()[-1])
    assert event["decision"] == "blocked"


def test_existing_output_collision_and_parent_file_fail_before_scan(state: AuthorizationStore, tmp_path: Path) -> None:
    """All export names are checked before traffic, preserving previous results and avoiding aliases."""
    existing = tmp_path / "existing.html"
    existing.write_text("keep")
    prefix = tmp_path / "review"
    parent_file = tmp_path / "regular"
    parent_file.write_text("keep")
    cases = [
        ["--output", str(existing)],
        ["--output", str(prefix), "--format", "all", "--result-json", str(prefix) + ".json"],
        ["--output", str(prefix), "--result-json", str(tmp_path / "folder" / ".." / "review")],
        ["--output", str(parent_file / "result")],
    ]
    with serve_web_lab() as lab:
        for extra in cases:
            assert main(["web", f"http://127.0.0.1:{lab.port}", "--checks", "cookies", *extra, *flags(state)]) == 1
        assert not lab.requests
    assert existing.read_text() == parent_file.read_text() == "keep"
    assert not (state.directory / "scans.log").exists()


def test_symlink_output_parent_fails_before_scan(state: AuthorizationStore, tmp_path: Path) -> None:
    """A symlink parent cannot redirect private output, including paths with normalization aliases."""
    real, alias = tmp_path / "real", tmp_path / "alias"
    real.mkdir()
    alias.symlink_to(real, target_is_directory=True)
    with serve_web_lab() as lab:
        for output in (alias / "result", alias / ".." / "result"):
            assert (
                main(
                    [
                        "web",
                        f"http://127.0.0.1:{lab.port}",
                        "--checks",
                        "cookies",
                        "--output",
                        str(output),
                        *flags(state),
                    ]
                )
                == 1
            )
        assert not lab.requests


def test_yaml_defaults_cli_override_and_wrong_mode_rejected(state: AuthorizationStore, tmp_path: Path) -> None:
    """Validated YAML applies only operational settings; command arguments can refine that selection."""
    config = tmp_path / "settings.yaml"
    config.write_text("checks: [headers]\nworkers: 1\nrate_limit: 1\n")
    native = tmp_path / "configured.json"
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply()
        assert (
            main(
                [
                    "web",
                    f"http://127.0.0.1:{lab.port}",
                    "--config",
                    str(config),
                    "--checks",
                    "cookies",
                    "--rate-limit",
                    "10",
                    "--result-json",
                    str(native),
                    *flags(state),
                ]
            )
            == 0
        )
    source = json.loads(native.read_text())
    assert [item["check"] for item in source["coverage"]] == ["cookies"]
    assert source["limits"]["rate_limit"] == 10
    assert main(["net", "127.0.0.1", "--config", str(config), "--ports", "80", *flags(state)]) == 1


def test_invalid_arguments_and_target_do_not_echo_secret(capsys: pytest.CaptureFixture[str]) -> None:
    """Parse and target validation errors contain authored categories without URL/argument tracebacks."""
    for arguments in (
        ["web", "http://localhost", "--threads", "synthetic-secret"],
        ["web", "http://user:synthetic-secret@localhost"],
        ["synthetic-secret"],
    ):
        assert main(arguments) == 1
    output = capsys.readouterr()
    assert "synthetic-secret" not in output.out + output.err
    assert "Traceback" not in output.err


def test_help_and_version_work_without_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Standard argparse help/version can be used safely in a fresh container or installation."""
    monkeypatch.setenv("VULNSCAN_STATE_DIR", str(tmp_path / "absent"))
    for arguments in (["--help"], ["--version"], ["web", "--help"], ["net", "--help"]):
        with pytest.raises(SystemExit) as exit_info:
            main(arguments)
        assert exit_info.value.code == 0
    assert not (tmp_path / "absent").exists()
