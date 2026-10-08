"""Integrate all ten checks and validate trusted resource bounds using real sockets."""

from scanner.checks.web import load_web_checks
from scanner.core.config import ScanConfig
from scanner.core.engine import ScanEngine
from scanner.core.target import Target
from scanner.safety.authorization import ScopeGate
from scanner.safety.budget import ScanControl
from scanner.safety.resolver import Resolution
from scanner.safety.state import AuthorizationStore
from scanner.utils.wordlists import load_wordlist, wordlist_path
from tests.web_lab import Reply, serve_web_lab
from tests.web_support import rule_registry


def test_all_checks_preserve_partial_coverage_and_findings(state: AuthorizationStore) -> None:
    """Unsupported TLS and absent query inputs cannot suppress header observations."""
    classes = load_web_checks()
    assert len(classes) == 10
    config = ScanConfig(timeout=0.2, weak_tls_probes=False)
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    control = ScanControl(config, clock=lambda: clock[0], sleep=sleep)
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply(headers=(("Content-Type", "text/html"), ("Set-Cookie", "synthetic=value")))
        result = ScanEngine(
            ScopeGate(state, resolver=lambda _: Resolution(("127.0.0.1",))), config, rule_registry(*classes)
        ).run(Target.web(lab.url), control=control)
        assert len(result.outcomes) == 10
        assert all(item.status.value != "failed" for item in result.outcomes)
        assert any(item.status.value == "inconclusive" for item in result.outcomes)
        assert any(item.status.value == "skipped" for item in result.outcomes)
        assert {"headers.csp", "cookies.attributes"} <= {item.rule_id for item in result.findings}
        assert all(item.cvss is None for item in result.findings)
        assert result.operation_counts["HTTP"] == len(lab.requests)
        assert all(item.method in {"GET", "HEAD", "OPTIONS"} for item in lab.requests)
        assert "synthetic=value" not in str(result.to_dict())


def test_wordlists_are_real_bounded_and_have_no_executable_xss_payloads() -> None:
    """Shipped path lists and one inert marker template are usable without substitutions."""
    assert "/.git/config" in load_wordlist("sensitive_files.txt")
    assert "/admin/" in load_wordlist("common_dirs.txt")
    payloads = load_wordlist("xss_payloads.txt")
    assert len(payloads) == 1 and "{marker}" in payloads[0]
    assert all(word not in payloads[0].lower() for word in ("<script", "javascript:", "onerror", "onload"))
    assert wordlist_path("sensitive_files.txt").is_file()
