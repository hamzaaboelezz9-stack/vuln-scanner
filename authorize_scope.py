"""Interactive authorization preflight; intentionally performs no service scan."""

import argparse
import json
import sys
from pathlib import Path

from scanner.core.target import Target, TargetError
from scanner.safety.authorization import ScopeGate
from scanner.safety.policy import Allowlist, CloudRangePolicy, ScopeError
from scanner.safety.state import LEGAL_NOTICE, AuthorizationStore


def main() -> int:
    """Show the first-run notice and inspect a web scope without HTTP requests."""
    parser = argparse.ArgumentParser(description="Authorize a scope without scanning it.")
    parser.add_argument("target", nargs="?", default="http://localhost:3000")
    parser.add_argument("--allowlist", type=Path, default=Path("allowlist.txt"))
    parser.add_argument("--policy", type=Path, default=Path("data/policy/cloud-ranges.json"))
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--i-have-permission", action="store_true")
    args = parser.parse_args()
    try:
        target = Target.web(args.target)
        state = AuthorizationStore(args.state_dir)
        if not state.acknowledged():
            print(LEGAL_NOTICE)
            state.acknowledge(input("> "))
        allowlist = Allowlist.from_file(args.allowlist)
        cloud = CloudRangePolicy.from_file(args.policy) if args.policy.exists() else None
        scope = ScopeGate(state, allowlist, cloud).authorize(target, args.i_have_permission)
        print(
            json.dumps(
                {
                    "scan_id": str(scope.scan_id),
                    "target": target.display,
                    "addresses": list(scope.addresses),
                    "ports": list(scope.ports),
                    "result": "Scope authorized. No service scan was performed.",
                },
                indent=2,
            )
        )
        return 0
    except (ScopeError, TargetError, EOFError, KeyboardInterrupt) as error:
        print(f"Preflight stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
