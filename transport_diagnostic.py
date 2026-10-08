"""A real read-only HTTP diagnostic; it performs no vulnerability evaluation."""

import argparse
import json
import sys
from pathlib import Path

from scanner.checks.base import BaseCheck, CheckContext, CheckInfo, CheckRegistry, CheckReport
from scanner.core.config import ConfigError, ScanConfig
from scanner.core.engine import ScanEngine
from scanner.core.target import ScanMode, Target, TargetError
from scanner.safety.authorization import ScopeGate
from scanner.safety.policy import Allowlist, CloudRangePolicy, ScopeError
from scanner.safety.state import LEGAL_NOTICE, AuthorizationStore

DIAGNOSTICS = CheckRegistry()


@DIAGNOSTICS.register(
    CheckInfo("transport_diagnostic", ScanMode.WEB, "Read-only transport diagnostic, not vulnerability detection", 32)
)
class TransportDiagnostic(BaseCheck):
    """Request status and headers through the approved transport; emit no findings."""

    def run(self, context: CheckContext) -> CheckReport:
        """Verify an HTTP exchange without collecting or persisting the response body."""
        context.http.request(context.target.url, read_body=False)
        return CheckReport()


def main() -> int:
    """Run the authorized diagnostic with first-run notice and origin-only JSON output."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--allowlist", type=Path, default=Path("allowlist.txt"))
    parser.add_argument("--policy", type=Path, default=Path("data/policy/cloud-ranges.json"))
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--ca-bundle")
    parser.add_argument("--i-have-permission", action="store_true")
    parser.add_argument("--i-know-what-im-doing", action="store_true")
    args = parser.parse_args()
    try:
        target = Target.web(args.target)
        overrides: dict[str, object] = {"checks": ("transport_diagnostic",)}
        if args.ca_bundle is not None:
            overrides["ca_bundle"] = args.ca_bundle
        config = ScanConfig.load(args.config, overrides)
        state = AuthorizationStore(args.state_dir)
        if not state.acknowledged():
            print(LEGAL_NOTICE)
            state.acknowledge(input("> "))
        allowlist = Allowlist.from_file(args.allowlist)
        cloud = CloudRangePolicy.from_file(args.policy) if args.policy.exists() else None
        engine = ScanEngine(ScopeGate(state, allowlist, cloud), config, DIAGNOSTICS)
        result = engine.run(target, args.i_have_permission, args.i_know_what_im_doing)
        print(
            json.dumps(
                {"purpose": "Transport diagnostic only; no vulnerability checks were performed.", **result.to_dict()},
                indent=2,
            )
        )
        return 0 if all(item.status.value == "complete" for item in result.outcomes) else 2
    except (ScopeError, TargetError, ConfigError, OSError, ValueError, EOFError):
        print(
            "Diagnostic stopped before completion; review configuration, authorization and local trust files.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print("Diagnostic interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
