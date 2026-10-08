"""Offline NVD candidates and a separate explicit, fixed-publisher cache updater."""

import argparse
import hashlib
import http.client
import json
import os
import re
import socket
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlencode

from scanner.core.cvss import CVSS31
from scanner.core.errors import TransportError
from scanner.core.network import CPE
from scanner.core.transport import verified_tls_context
from scanner.safety.io_deadline import IODeadline
from scanner.safety.policy import aware_time, canonical_ip, hard_blocked
from scanner.safety.rate_limit import RateLimiter
from scanner.safety.resolver import DNSResolver
from scanner.safety.state import AuthorizationStore
from scanner.utils.http import _BoundedHTTPResponse

NVD_HOST = "services.nvd.nist.gov"
NVD_PATH = "/rest/json/cves/2.0"
NVD_SOURCE = "https://" + NVD_HOST + NVD_PATH
NVD_TIMEOUT = 15.0
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_NVD_RESULTS = 100
CACHE_AGE = timedelta(days=7)
NVD_INTERVAL = 6.1
CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,12}\Z")


class CatalogError(ValueError):
    """Catalog absence, stale data or invalid publisher/cache content prevents assurance."""


@dataclass(frozen=True)
class Candidate:
    """Published advisory ID and optional 3.1 vector; not verified target applicability."""

    identifier: str
    cvss: CVSS31 | None = None

    def __post_init__(self) -> None:
        """Require a bounded advisory ID and validated native CVSS object."""
        if not isinstance(self.identifier, str) or not CVE_ID.fullmatch(self.identifier):
            raise CatalogError("Invalid catalog advisory identifier.")
        if self.cvss is not None and not isinstance(self.cvss, CVSS31):
            raise CatalogError("Invalid catalog score.")


@dataclass(frozen=True)
class CatalogResult:
    """A cache entry bound to a concrete CPE with explicit pagination/freshness."""

    cpe: str
    candidates: tuple[Candidate, ...]
    captured_at: datetime
    complete: bool

    def __post_init__(self) -> None:
        """Reject unsafe queries, duplicate advisories, future dates and unbounded entries."""
        if not CPE.fullmatch(self.cpe) or type(self.complete) is not bool:
            raise CatalogError("Invalid concrete CPE cache entry.")
        if self.captured_at.utcoffset() is None or self.captured_at > datetime.now(timezone.utc):
            raise CatalogError("Invalid cache timestamp.")
        if (
            len(self.candidates) > MAX_NVD_RESULTS
            or any(not isinstance(c, Candidate) for c in self.candidates)
            or len({c.identifier for c in self.candidates}) != len(self.candidates)
        ):
            raise CatalogError("Invalid catalog candidate list.")

    def to_dict(self) -> dict[str, object]:
        """Persist compact public metadata; omit descriptions, configuration text and targets."""
        return {
            "schema": "vulnscanner.nvd-cache.v1",
            "source": NVD_SOURCE,
            "cpe": self.cpe,
            "captured_at": self.captured_at.isoformat(),
            "complete": self.complete,
            "candidates": [{"id": c.identifier, "vector": c.cvss.vector if c.cvss else None} for c in self.candidates],
        }


def parse_nvd(payload: bytes, cpe: str) -> CatalogResult:
    """Parse one filtered NVD API page; never implement local vulnerable-version ranges."""
    try:
        if len(payload) > MAX_CATALOG_BYTES or not CPE.fullmatch(cpe):
            raise ValueError("Invalid payload/query bounds.")
        data = json.loads(payload)
        items = data["vulnerabilities"]
        total, start = data["totalResults"], data["startIndex"]
        if (
            data["format"] != "NVD_CVE"
            or data["version"] != "2.0"
            or type(total) is not int
            or total < 0
            or type(start) is not int
            or start != 0
            or not isinstance(items, list)
            or len(items) > MAX_NVD_RESULTS
            or len(items) > total
        ):
            raise ValueError("Unsupported NVD page.")
        candidates = []
        for item in items:
            cve = item["cve"]
            if cve.get("vulnStatus") == "Rejected":
                continue
            score = None
            metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
            if not isinstance(metrics, list) or len(metrics) > 20:
                raise ValueError("Invalid catalog metric list.")
            # Prefer NVD's own metric, then another primary publisher metric.
            metrics = sorted(metrics, key=lambda m: (m.get("source") != "nvd@nist.gov", m.get("type") != "Primary"))
            for metric in metrics:
                value = metric["cvssData"]
                if value["version"] != "3.1":
                    raise ValueError("Mismatched catalog metric version.")
                computed = CVSS31(value["vectorString"])
                if type(value["baseScore"]) not in {int, float} or computed.score != value["baseScore"]:
                    raise ValueError("Catalog score does not match its vector.")
                if score is None:
                    score = computed
            candidates.append(Candidate(cve["id"], score))
        return CatalogResult(cpe, tuple(candidates), datetime.now(timezone.utc), len(items) == total)
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as error:
        raise CatalogError("NVD response could not be validated; prior cache is preserved.") from error


class NVDCache:
    """Owner-only compact cache; scans read it offline and never fetch automatically."""

    def __init__(self, directory: Path) -> None:
        """Reuse private state file checks without requiring or creating scan acknowledgment."""
        self.store = AuthorizationStore(directory)

    def _name(self, cpe: str) -> str:
        if not CPE.fullmatch(cpe):
            raise CatalogError("A concrete supported product CPE is required.")
        return hashlib.sha256(cpe.encode("ascii")).hexdigest() + ".json"

    def lookup(self, cpe: str) -> CatalogResult:
        """Fail on absent, stale, mismatched, unsafe or corrupt entries; never imply clean."""
        try:
            descriptor = self.store._open(self._name(cpe), os.O_RDONLY)
            with os.fdopen(descriptor, "rb") as source:
                raw = source.read(MAX_CATALOG_BYTES + 1)
            if len(raw) > MAX_CATALOG_BYTES:
                raise CatalogError("Cache entry exceeds its cap.")
            data = json.loads(raw)
            if (
                data["schema"] != "vulnscanner.nvd-cache.v1"
                or data["source"] != NVD_SOURCE
                or data["cpe"] != cpe
                or not isinstance(data["candidates"], list)
                or len(data["candidates"]) > MAX_NVD_RESULTS
            ):
                raise CatalogError("Cache identity or candidate bounds are invalid.")
            result = CatalogResult(
                cpe,
                tuple(
                    Candidate(item["id"], CVSS31(item["vector"]) if item["vector"] is not None else None)
                    for item in data["candidates"]
                ),
                aware_time(data["captured_at"]),
                data["complete"],
            )
            if datetime.now(timezone.utc) - result.captured_at > CACHE_AGE:
                raise CatalogError("Catalog cache is older than seven days.")
            return result
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as error:
            raise CatalogError("Catalog cache is absent, stale, unsafe or invalid.") from error

    def save(self, result: CatalogResult) -> None:
        """Atomically replace one owner-only entry; refuse existing symlinks/special files."""
        name = self._name(result.cpe)
        temporary = None
        try:
            try:
                descriptor = self.store._open(name, os.O_RDONLY)
            except FileNotFoundError:
                pass
            else:
                os.close(descriptor)
            descriptor, temporary = tempfile.mkstemp(prefix="nvd-", dir=self.store.directory)
            with os.fdopen(descriptor, "w", encoding="utf-8") as target:
                json.dump(result.to_dict(), target)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.store.directory / name)
        finally:
            if temporary is not None and Path(temporary).exists():
                Path(temporary).unlink()


def fetch_nvd(cpe: str) -> bytes:
    """Fetch only filtered public NVD metadata over verified, bounded, proxy-free HTTPS."""
    if not isinstance(cpe, str) or not CPE.fullmatch(cpe):
        raise CatalogError("Unsafe catalog query.")
    # This fixed publisher fetch is separate from target scanning. No target host,
    # address, credentials or full greeting is supplied; only a public product CPE.
    resolution = DNSResolver()(NVD_HOST)
    address = canonical_ip(resolution.addresses[0])
    if not address.is_global or hard_blocked(address):
        raise CatalogError("Catalog publisher resolved to a prohibited non-public address.")
    guard = IODeadline(NVD_TIMEOUT)
    tls = verified_tls_context()
    connection = http.client.HTTPSConnection(NVD_HOST, timeout=NVD_TIMEOUT, context=tls)
    connection.response_class = _BoundedHTTPResponse
    connection.set_debuglevel(0)
    raw: socket.socket | None = None
    try:
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        raw = socket.socket(family, socket.SOCK_STREAM)
        guard.watch(raw)
        raw.settimeout(guard.remaining())
        raw.connect((str(address), 443, 0, 0) if family == socket.AF_INET6 else (str(address), 443))
        connection.sock = tls.wrap_socket(raw, server_hostname=NVD_HOST, do_handshake_on_connect=False)
        raw = None
        guard.watch(connection.sock)
        connection.sock.settimeout(guard.remaining())
        connection.sock.do_handshake()
        query = urlencode(
            {"cpeName": cpe, "isVulnerable": "", "noRejected": "", "resultsPerPage": MAX_NVD_RESULTS, "startIndex": 0}
        )
        connection.request(
            "GET",
            NVD_PATH + "?" + query,
            headers={
                "User-Agent": "VulnScanner/1.0 (authorized-testing-only; explicit-catalog-update)",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            },
        )
        with connection.getresponse() as response:
            if (
                response.status != 200
                or response.getheader("Content-Encoding", "identity").lower() != "identity"
                or response.getheader("Content-Type", "").split(";", 1)[0].lower() != "application/json"
            ):
                raise CatalogError(
                    "Catalog publisher returned unsupported status/content; no redirects or retries follow."
                )
            payload = response.read(MAX_CATALOG_BYTES + 1)
            if len(payload) > MAX_CATALOG_BYTES:
                raise CatalogError("Catalog response exceeds its byte cap.")
            return payload
    except (OSError, http.client.HTTPException, TransportError) as error:
        raise CatalogError("Verified catalog fetch failed; no insecure fallback was used.") from error
    finally:
        if raw is not None:
            raw.close()
        connection.close()
        guard.close()


class NVDUpdater:
    """Explicit publisher updater with separate public-rate pacing and an injectable fetch."""

    def __init__(
        self, cache: NVDCache, fetch: Callable[[str], bytes] = fetch_nvd, limiter: RateLimiter | None = None
    ) -> None:
        """Keep tests offline; production updater sends only concrete public CPE identifiers."""
        self.cache, self.fetch = cache, fetch
        self.limiter = limiter or RateLimiter(1 / NVD_INTERVAL)

    def update(self, cpe: str) -> CatalogResult:
        """Perform one page lookup, validate all data and preserve old cache on any failure."""
        if not CPE.fullmatch(cpe):
            raise CatalogError("Unsafe catalog query.")
        self.limiter.acquire()
        result = parse_nvd(self.fetch(cpe), cpe)
        self.cache.save(result)
        return result


def main() -> int:
    """CLI for explicit catalog refresh, independent of any target scan or authorization."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpe", required=True, nargs="+")
    parser.add_argument("--cache-dir", type=Path, default=Path.home() / ".vulnscanner" / "nvd")
    args = parser.parse_args()
    try:
        if len(args.cpe) > 10:
            raise CatalogError("Refresh at most ten concrete product versions per invocation.")
        updater = NVDUpdater(NVDCache(args.cache_dir))
        for cpe in args.cpe:
            result = updater.update(cpe)
            print(
                json.dumps(
                    {
                        "purpose": "Explicit public NVD catalog update; no target scan.",
                        "candidates": len(result.candidates),
                        "complete": result.complete,
                    }
                )
            )
        return 0
    except (CatalogError, OSError, ValueError):
        print(
            "Catalog refresh failed; existing valid entries were preserved. Check publisher access/query and private cache permissions.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
