"""Synthetic catalog responses test matching/cache mechanics, not real CVE assertions."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scanner.checks.network import load_network_checks
from scanner.core.config import ScanConfig
from scanner.core.engine import ScanEngine
from scanner.core.target import Target
from scanner.safety.authorization import ScopeGate
from scanner.safety.rate_limit import RateLimiter
from scanner.safety.state import AuthorizationStore
from scanner.utils.cve import Candidate, CatalogError, CatalogResult, NVDCache, NVDUpdater, parse_nvd
from tests.network_lab import greeting_lab
from tests.web_support import rule_registry

CPE = "cpe:2.3:a:openbsd:openssh:9.8:p1:*:*:*:*:*:*"
SYNTHETIC_ID = "CVE-2099-99999"
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def payload(total: int = 1, rejected: bool = False, score: float = 9.8) -> bytes:
    """Create fictional future advisory data only for validating parser behavior."""
    return json.dumps(
        {
            "format": "NVD_CVE",
            "version": "2.0",
            "startIndex": 0,
            "totalResults": total,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": SYNTHETIC_ID,
                        "vulnStatus": "Rejected" if rejected else "Analyzed",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                    "cvssData": {"version": "3.1", "vectorString": VECTOR, "baseScore": score},
                                }
                            ]
                        },
                    }
                }
            ],
        }
    ).encode()


def test_validated_catalog_keeps_published_score_separate(tmp_path: Path) -> None:
    """Native vectors reproduce published scores; freshness and concrete CPE are bound."""
    entry = parse_nvd(payload(), CPE)
    assert entry.complete and entry.candidates[0].cvss.score == 9.8
    cache = NVDCache(tmp_path / "cache")
    cache.save(entry)
    assert cache.lookup(CPE) == entry
    assert cache.store.directory.stat().st_mode & 0o777 == 0o700
    files = list(cache.store.directory.glob("*.json"))
    assert len(files) == 1 and files[0].stat().st_mode & 0o777 == 0o600
    assert "description" not in files[0].read_text()


def test_catalog_rejection_pagination_and_invalid_score() -> None:
    """Rejected advisories are omitted; incomplete pages and inconsistent scores stay explicit."""
    assert not parse_nvd(payload(rejected=True), CPE).candidates
    assert not parse_nvd(payload(total=120), CPE).complete
    with pytest.raises(CatalogError):
        parse_nvd(payload(score=3.1), CPE)
    with pytest.raises(CatalogError):
        parse_nvd(b"{}", CPE)
    with pytest.raises(CatalogError):
        parse_nvd(payload(), "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")


def test_absent_stale_future_mismatched_and_symlink_entries_fail(tmp_path: Path) -> None:
    """Cache failure never means zero known vulnerabilities or invokes external IO."""
    cache = NVDCache(tmp_path / "cache")
    with pytest.raises(CatalogError):
        cache.lookup(CPE)
    stale = CatalogResult(CPE, (), datetime.now(timezone.utc) - timedelta(days=8), True)
    cache.save(stale)
    with pytest.raises(CatalogError):
        cache.lookup(CPE)
    with pytest.raises(CatalogError):
        CatalogResult(CPE, (), datetime.now(timezone.utc) + timedelta(minutes=1), True)
    file = next(cache.store.directory.glob("*.json"))
    data = json.loads(file.read_text())
    data["cpe"] = data["cpe"].replace("9.8", "9.9")
    file.write_text(json.dumps(data))
    with pytest.raises(CatalogError):
        cache.lookup(CPE)
    file.unlink()
    os.symlink(tmp_path / "not-private", file)
    with pytest.raises(CatalogError):
        cache.lookup(CPE)
    with pytest.raises(OSError):
        cache.save(parse_nvd(payload(), CPE))


def test_updater_is_paced_and_failed_parse_preserves_cache(tmp_path: Path) -> None:
    """Injecting synthetic publisher bytes exercises the real updater without public traffic."""
    cache = NVDCache(tmp_path / "cache")
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    updater = NVDUpdater(
        cache, fetch=lambda _: payload(), limiter=RateLimiter(1 / 6.1, clock=lambda: clock[0], sleep=sleep)
    )
    updater.update(CPE)
    updater.update(CPE)
    assert clock[0] == pytest.approx(6.1)
    file = next(cache.store.directory.glob("*.json"))
    original = file.read_bytes()
    updater.fetch = lambda _: b"invalid json"
    with pytest.raises(CatalogError):
        updater.update(CPE)
    assert file.read_bytes() == original


def test_cached_cve_candidates_do_not_become_confirmed_target_cvss(state: AuthorizationStore, tmp_path: Path) -> None:
    """The real network engine consumes cache candidates but sends no external query."""
    cache = NVDCache(tmp_path / "cache")
    cache.save(parse_nvd(payload(), CPE))
    with greeting_lab() as lab:
        config = ScanConfig(checks=("cves",), cve_cache=str(cache.store.directory), timeout=0.5)
        result = ScanEngine(ScopeGate(state), config, rule_registry(*load_network_checks())).run(
            Target.net("127.0.0.1"), ports=(lab.port,)
        )
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.confidence.value == "needs-manual-verification" and finding.cvss is None
        assert SYNTHETIC_ID in str(finding.evidence.observations)
        assert "published CVSS" in str(finding.evidence.observations)
        assert result.outcomes[0].status.value == "inconclusive"
        assert result.operation_counts == {"HTTP": 0, "TCP": 1, "TLS": 0}
        assert "cve_cache" not in result.limits


def test_missing_cache_skips_before_target_io(state: AuthorizationStore) -> None:
    """The CVE-only check without an explicit cache cannot quietly fetch from the Internet."""
    with greeting_lab() as lab:
        config = ScanConfig(checks=("cves",))
        result = ScanEngine(ScopeGate(state), config, rule_registry(*load_network_checks())).run(
            Target.net("127.0.0.1"), ports=(lab.port,)
        )
        assert lab.connections == 0 and not result.findings
        assert result.outcomes[0].status.value == "skipped"


def test_advisory_identifier_validation() -> None:
    """Untrusted CVE IDs cannot inject terminal controls or arbitrary reference URLs."""
    with pytest.raises(CatalogError):
        Candidate("CVE-2025-1234\n<script>")


def test_publisher_fetch_rejects_private_dns_and_wildcard_before_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fixed catalog updater cannot be redirected into a local/metadata target."""
    from scanner.safety.resolver import Resolution
    from scanner.utils import cve

    monkeypatch.setattr(cve, "DNSResolver", lambda: lambda _: Resolution(("127.0.0.1",)))
    with pytest.raises(CatalogError):
        cve.fetch_nvd(CPE)
    with pytest.raises(CatalogError):
        cve.fetch_nvd("http://169.254.169.254")
