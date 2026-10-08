"""Reproducible measured local fixture; this is not a scan of OWASP Juice Shop."""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from scanner.safety.state import PERMISSION_PHRASE, AuthorizationStore
from tests.web_lab import Reply, Request, serve_web_lab

CANARY_PATH = "/vulnscanner-canary-" + "a" * 32 + ".txt"
CANARY_TOKEN = "vulnscanner-canary-" + "b" * 32


def page(request: Request) -> Reply:
    """Intentionally synthesize input/CORS/cookie signals; never execute a payload."""
    headers = (
        ("Content-Type", "text/html"),
        ("Set-Cookie", "synthetic_demo=value"),
        ("Server", "SyntheticDemo"),
        ("Allow", "GET, HEAD, OPTIONS, PUT, DELETE, TRACE"),
    )
    origin = request.headers.get("Origin")
    if origin:
        headers += (("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true"))
    if request.value("next").startswith("https://"):
        return Reply(302, headers=headers + (("Location", request.value("next")),))
    if request.value("file") == "../" + CANARY_PATH.lstrip("/"):
        return Reply(body=CANARY_TOKEN.encode(), headers=headers)
    if "'" in request.value("id"):
        return Reply(body=b"You have an error in your SQL syntax; synthetic demo", headers=headers)
    body = '<!-- secret=dummy-comment --><script src="/app.js"></script><p>' + request.value("q") + "</p>"
    return Reply(body=body.encode(), headers=headers)


def generate() -> dict[str, object]:
    """Use the shipped runner, actual global pacing and isolated acknowledged state."""
    with TemporaryDirectory(prefix="vulnscanner-web-demo-") as directory, serve_web_lab() as lab:
        root = Path(directory)
        state = AuthorizationStore(root / "operator")
        state.acknowledge(PERMISSION_PHRASE)
        config = root / "demo.yaml"
        config.write_text(
            f"timeout: 0.3\ntraversal_canary_path: {CANARY_PATH}\ntraversal_canary_token: {CANARY_TOKEN}\n",
            encoding="utf-8",
        )
        lab.routes["/search"] = page
        lab.routes["/.env"] = Reply(body=b"DUMMY_CONFIG=unused", headers=(("Content-Type", "text/plain"),))
        lab.routes["/admin/"] = Reply()
        lab.routes["/uploads/"] = Reply(body=b'<h1>Index of /uploads/</h1><a href="one">one</a><a href="two">two</a>')
        lab.routes["/robots.txt"] = Reply(body=b"User-agent: *\nDisallow: /demo-private-route\n")
        lab.routes["/app.js"] = Reply(body=b"const publicValue = 1;\n//# sourceMappingURL=app.js.map")
        lab.routes["/app.js.map"] = Reply(body=b"{}", headers=(("Content-Type", "application/json"),))
        lab.routes[CANARY_PATH] = Reply(body=CANARY_TOKEN.encode(), headers=(("Content-Type", "text/plain"),))
        url = f"http://127.0.0.1:{lab.port}/search?q=hello&id=1&next=%2Fsafe&file=public.txt"
        executed = subprocess.run(
            [
                sys.executable,
                "examples/web_checks.py",
                url,
                "--config",
                str(config),
                "--state-dir",
                str(root / "operator"),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=45,
        )
        if executed.returncode not in {0, 2}:
            raise RuntimeError("The local demonstration runner did not complete.")
        measured = json.loads(executed.stdout)
        if any(item["status"] == "failed" for item in measured["coverage"]):
            raise RuntimeError("A local demonstration check unexpectedly failed.")
        return {
            "purpose": "Measured synthetic loopback web fixture; not OWASP Juice Shop or a production assessment.",
            "runner_exit_code": executed.returncode,
            **measured,
        }


def main() -> int:
    """Write actual measured sample output without fabricating scan metadata."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("docs/WEB_SAMPLE.json"))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
