"""Run anonymous web checks with native JSON output; the full CLI is scanner.cli."""

import argparse
import json
import sys
from pathlib import Path

from scanner.checks.web import load_web_checks
from scanner.core.config import ConfigError, ScanConfig
from scanner.core.engine import ScanEngine
from scanner.core.target import Target, TargetError
from scanner.safety.authorization import ScopeGate
from scanner.safety.policy import Allowlist, CloudRangePolicy, ScopeError
from scanner.safety.state import LEGAL_NOTICE, AuthorizationStore


def main() -> int:
    """Validate settings and permissions, then emit sanitized findings and honest coverage."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--checks", help="Comma-separated built-in names; default: all ten web checks")
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--allowlist", type=Path, default=Path("allowlist.txt"))
    parser.add_argument("--policy", type=Path, default=Path("data/policy/cloud-ranges.json"))
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--ca-bundle")
    parser.add_argument("--i-have-permission", action="store_true")
    parser.add_argument("--i-know-what-im-doing", action="store_true")
    args = parser.parse_args()
    try:
        load_web_checks()
        target = Target.web(args.target)
        overrides: dict[str, object] = {}
        if args.checks is not None:
            overrides["checks"] = tuple(value.strip() for value in args.checks.split(","))
        if args.ca_bundle is not None:
            overrides["ca_bundle"] = args.ca_bundle
        config = ScanConfig.load(args.config, overrides)
        state = AuthorizationStore(args.state_dir)
        if not state.acknowledged():
            # The notice goes to stderr so stdout stays machine-readable JSON.
            print(LEGAL_NOTICE, file=sys.stderr)
            print("> ", end="", file=sys.stderr, flush=True)
            state.acknowledge(input())
        allowlist = Allowlist.from_file(args.allowlist)
        cloud = CloudRangePolicy.from_file(args.policy) if args.policy.exists() else None
        result = ScanEngine(ScopeGate(state, allowlist, cloud), config).run(
            target, args.i_have_permission, args.i_know_what_im_doing
        )
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if all(item.status.value == "complete" for item in result.outcomes) else 2
    except (ScopeError, TargetError, ConfigError, OSError, ValueError, EOFError):
        print("Web assessment stopped; review scope, configuration and local trust files.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Web assessment interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
