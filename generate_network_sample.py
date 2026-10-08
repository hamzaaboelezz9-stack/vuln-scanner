"""Measured synthetic loopback network sample; no public target or invented CVE scan."""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from scanner.safety.state import PERMISSION_PHRASE, AuthorizationStore
from tests.network_lab import greeting_lab, unused_port


def generate() -> dict[str, object]:
    """Launch the shipped runner with real pacing against two synthetic local greetings."""
    with (
        TemporaryDirectory(prefix="vulnscanner-net-demo-") as directory,
        greeting_lab() as ssh,
        greeting_lab((b"220 Synthetic host ESMTP public greeting\r\n",)) as smtp,
    ):
        root = Path(directory)
        state = AuthorizationStore(root / "operator")
        state.acknowledge(PERMISSION_PHRASE)
        config = root / "demo.yaml"
        config.write_text("timeout: 0.5\nnetwork_banner_seconds: 0.2\n", encoding="utf-8")
        closed = unused_port()
        executed = subprocess.run(
            [
                sys.executable,
                "examples/network_checks.py",
                "127.0.0.1",
                "--ports",
                f"{ssh.port},{smtp.port},{closed}",
                "--config",
                str(config),
                "--state-dir",
                str(root / "operator"),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if executed.returncode not in {0, 2}:
            raise RuntimeError("The measured network runner failed.")
        measured = json.loads(executed.stdout)
        if any(item["status"] == "failed" for item in measured["coverage"]):
            raise RuntimeError("A network demo check unexpectedly failed.")
        if (
            measured["operations"]["TCP"] != 3
            or ssh.connections != 1
            or smtp.connections != 1
            or any(ssh.received + smtp.received)
        ):
            raise RuntimeError("The measured demo did not preserve single-connect/passive behavior.")
        return {
            "purpose": "Measured synthetic loopback TCP fixture; banners are simulated, not verified installed services. No live NVD or Juice Shop assessment.",
            "runner_exit_code": executed.returncode,
            **measured,
        }


def main() -> int:
    """Write actual scan metadata/observations and explicitly label synthetic identities."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("docs/NETWORK_SAMPLE.json"))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
