"""Run an authorized passive TCP survey with native JSON output; full CLI: scanner.cli."""

import argparse
import json
import sys
from pathlib import Path

from scanner.checks.network import load_network_checks
from scanner.core.config import ConfigError, ScanConfig
from scanner.core.engine import ScanEngine
from scanner.core.target import Target, TargetError
from scanner.safety.authorization import ScopeGate
from scanner.safety.policy import Allowlist, CloudRangePolicy, ScopeError
from scanner.safety.state import LEGAL_NOTICE, AuthorizationStore
from scanner.utils.ports import parse_ports


def main() -> int:
    """Apply scope and budgets, then emit minimal observations and explicit unknowns."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--ports", default="common1000", help="Ports/ranges, common100/common1000 or top100/top1000")
    parser.add_argument("--port-db", type=Path, help="Explicit local nmap-services frequency file for a top preset")
    parser.add_argument("--checks", help="Comma-separated discovery,ports,services,cves; default: all")
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--allowlist", type=Path, default=Path("allowlist.txt"))
    parser.add_argument("--policy", type=Path, default=Path("data/policy/cloud-ranges.json"))
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--cve-cache", type=Path)
    parser.add_argument("--threads", type=int)
    parser.add_argument("--rate-limit", type=float)
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--i-have-permission", action="store_true")
    parser.add_argument("--i-know-what-im-doing", action="store_true")
    args = parser.parse_args()
    try:
        load_network_checks()
        target = Target.net(args.target)
        ports = parse_ports(args.ports, args.port_db)
        overrides: dict[str, object] = {}
        for attribute, setting in (("threads", "workers"), ("rate_limit", "rate_limit"), ("timeout", "timeout")):
            value = getattr(args, attribute)
            if value is not None:
                overrides[setting] = value
        if args.checks is not None:
            overrides["checks"] = tuple(value.strip() for value in args.checks.split(","))
        if args.cve_cache is not None:
            overrides["cve_cache"] = str(args.cve_cache)
        config = ScanConfig.load(args.config, overrides)
        state = AuthorizationStore(args.state_dir)
        if not state.acknowledged():
            print(LEGAL_NOTICE, file=sys.stderr)
            print("> ", end="", file=sys.stderr, flush=True)
            state.acknowledge(input())
        allowlist = Allowlist.from_file(args.allowlist)
        cloud = CloudRangePolicy.from_file(args.policy) if args.policy.exists() else None
        result = ScanEngine(ScopeGate(state, allowlist, cloud), config).run(
            target, args.i_have_permission, args.i_know_what_im_doing, ports=ports
        )
        basis = (
            "operator-supplied TCP frequency data"
            if args.port_db
            else "curated coverage preset; not a popularity ranking"
            if args.ports in {"top100", "top1000", "common100", "common1000"}
            else "operator-selected exact ports/ranges"
        )
        print(json.dumps({"port_selection_basis": basis, **result.to_dict()}, indent=2))
        return 0 if all(item.status.value == "complete" for item in result.outcomes) else 2
    except (ScopeError, TargetError, ConfigError, OSError, ValueError, EOFError):
        print(
            "Network assessment stopped; review scope, port selection, configuration, budgets and local files.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print("Network assessment interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
