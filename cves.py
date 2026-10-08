"""Read cached exact-CPE advisory candidates; never assert exploitation from banners."""

from pathlib import Path

from scanner.checks.base import BaseCheck, CheckContext, CheckInfo, CheckReport, register_check
from scanner.checks.network.common import MAX_NETWORK_FINDINGS, report, survey_result
from scanner.core.config import MAX_OPERATIONS
from scanner.core.finding import Confidence, Evidence, Finding, Severity
from scanner.core.result import CheckStatus
from scanner.core.target import ScanMode
from scanner.utils.cve import CatalogError, NVDCache

MAX_CANDIDATES_PER_SERVICE = 5


@register_check(
    CheckInfo(
        "cves",
        ScanMode.NETWORK,
        "Offline NVD exact-CPE candidates with freshness and unverified-identity limits",
        MAX_OPERATIONS,
    )
)
class CVECheck(BaseCheck):
    """Keep catalog severity separate from a verified target exploit/CVSS assessment."""

    def run(self, context: CheckContext) -> CheckReport:
        """Use only a prepopulated local cache; missing data never becomes a clean result."""
        if context.config.cve_cache is None:
            return CheckReport(
                status=CheckStatus.SKIPPED, reason="No NVD cache configured; no external lookup was made."
            )
        cache = NVDCache(Path(context.config.cve_cache))
        result = survey_result(context)
        findings = []
        notes = []
        catalog = {}
        for item in result.observations:
            if item.service is None or item.service.cpe is None:
                continue
            cpe = item.service.cpe
            if cpe not in catalog:
                try:
                    catalog[cpe] = cache.lookup(cpe)
                except CatalogError:
                    catalog[cpe] = None
            entry = catalog[cpe]
            if entry is None:
                notes.append(
                    "Some recognized product versions lack fresh validated cache data; advisory coverage is unknown."
                )
                continue
            if not entry.complete or len(entry.candidates) > MAX_CANDIDATES_PER_SERVICE:
                notes.append(
                    "Catalog pagination or the five-candidate-per-service display cap leaves additional advisories unreviewed."
                )
            candidates = entry.candidates[:MAX_CANDIDATES_PER_SERVICE]
            if not candidates:
                continue
            if len(findings) <= MAX_NETWORK_FINDINGS:
                details = tuple(
                    c.identifier
                    + (
                        f"; published CVSS 3.1 base {c.cvss.score} ({c.cvss.vector})"
                        if c.cvss
                        else "; no validated CVSS 3.1 metric"
                    )
                    for c in candidates
                )
                findings.append(
                    Finding(
                        "network.cve_candidate",
                        "Cached advisories match an advertised product version",
                        Severity.INFO,
                        Confidence.POTENTIAL,
                        "NVD returned these candidates for the concrete banner-derived CPE. Product identity, distro backports, enabled modules, environment prerequisites and patch status are unverified. Catalog base scores are advisory metadata, not a verified target CVSS or proof of exploitation. [Needs manual verification].",
                        Evidence("TCP", item.endpoint, details),
                        "Have the authorized administrator verify installed package/build, vendor advisories, backported patches and configuration prerequisites. Apply applicable supported updates and restrict exposure. Do not test exploit payloads to infer patch status.",
                        tuple("https://nvd.nist.gov/vuln/detail/" + c.identifier for c in candidates),
                    )
                )
        if not catalog:
            notes.append(
                "No observed service supplied a supported concrete software CPE; applicability could not be evaluated."
            )
        # Even an empty exact-CPE catalog is not proof of installed patch status.
        notes.append(
            "Banner identity and catalog applicability remain unverified; no exploit or authenticated inventory was performed."
        )
        return report(result, tuple(findings), tuple(dict.fromkeys(notes)))
