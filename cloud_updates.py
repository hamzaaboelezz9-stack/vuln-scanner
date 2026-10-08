"""Refresh cloud policy from fixed official HTTPS sources, never scan targets."""

import argparse
import hashlib
import json
import logging
import os
import re
import ssl
import tempfile
from datetime import datetime, timedelta, timezone
from ipaddress import collapse_addresses, ip_network
from pathlib import Path
from typing import IO, Callable
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from scanner.safety.policy import CloudRangePolicy, ScopeError, publisher_url

AWS_FEED = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GOOGLE_FEED = "https://www.gstatic.com/ipranges/goog.json"
AZURE_DOWNLOAD_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
FEED_TIMEOUT = 15.0
MAX_FEED_BYTES = 32 * 1024 * 1024
MAX_UTC_OFFSET = timedelta(hours=14)
LOGGER = logging.getLogger(__name__)


class NoRedirects(HTTPRedirectHandler):
    """Publisher updates never follow a redirect to an unapproved destination."""

    def redirect_request(self, req: Request, fp: IO[bytes], code: int, msg: str, headers: object, newurl: str) -> None:
        """Return no replacement request; urllib raises an HTTP redirect error."""
        return None


def _fetch(url: str) -> bytes:
    if url != AZURE_DOWNLOAD_PAGE and not any(publisher_url(provider, url) for provider in ("aws", "azure", "google")):
        raise ScopeError("Policy updates may only fetch configured official publisher URLs.")
    # No environment proxies or SSLKEYLOGFILE: publisher TLS verifies host/chain.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirects())
    request = Request(url, headers={"User-Agent": "VulnScanner/0.1 (authorized-testing-only; policy-update)"})
    with opener.open(request, timeout=FEED_TIMEOUT) as response:
        if response.status != 200:
            raise ScopeError("Publisher did not return a successful policy response.")
        payload = response.read(MAX_FEED_BYTES + 1)
        if len(payload) > MAX_FEED_BYTES:
            raise ScopeError("Publisher response exceeds the policy size budget.")
        return payload


def _collapse(values: list[str]) -> list[str]:
    networks = [ip_network(value, strict=True) for value in values]
    if not networks or any(network.prefixlen == 0 for network in networks):
        raise ScopeError("Publisher ranges are empty or contain a default route.")
    result: list[str] = []
    for version in (4, 6):
        result.extend(
            str(network)
            for network in collapse_addresses(network for network in networks if network.version == version)
        )
    return result


def refresh_policy(destination: Path, fetch: Callable[[str], bytes] | None = None) -> CloudRangePolicy:
    """Fetch complete feeds, validate them and atomically replace the local snapshot.

    Hashes identify the source bytes. They are not digital signatures and do not
    protect against an attacker who can already modify the local policy or code.
    """
    temporary: str | None = None
    fetch = fetch or _fetch
    try:
        page = fetch(AZURE_DOWNLOAD_PAGE).decode("utf-8")
        candidates = set(re.findall(r"https://download\.microsoft\.com/[^\s\"<>]+\.json", page))
        azure_urls = sorted(url for url in candidates if publisher_url("azure", url))
        if not azure_urls:
            raise ScopeError("Microsoft's current Azure feed could not be identified.")
        # Sort by the explicit publication date, not incidental download-directory IDs.
        azure_url = max(azure_urls, key=lambda url: url.rsplit("_", 1)[1])
        sources: dict[str, object] = {}
        for provider, url in (("aws", AWS_FEED), ("azure", azure_url), ("google", GOOGLE_FEED)):
            payload = fetch(url)
            feed = json.loads(payload)
            if provider == "aws":
                values = [item["ip_prefix"] for item in feed["prefixes"]]
                values += [item["ipv6_prefix"] for item in feed["ipv6_prefixes"]]
                # AWS defines createDate as YYYY-MM-DD-HH-MM-SS in UTC.
                published = datetime.strptime(feed["createDate"], "%Y-%m-%d-%H-%M-%S").replace(tzinfo=timezone.utc)
                basis = "AWS createDate specifies UTC."
            elif provider == "google":
                values = [item.get("ipv4Prefix") or item["ipv6Prefix"] for item in feed["prefixes"]]
                # A timezone-less timestamp is ambiguous. The earliest plausible
                # UTC instant makes freshness conservative instead of guessing UTC.
                timestamp = feed["creationTime"]
                if not isinstance(timestamp, str):
                    raise ValueError("Google publication timestamp must be text.")
                published = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if published.utcoffset() is None:
                    published = published.replace(tzinfo=timezone.utc) - MAX_UTC_OFFSET
                    basis = "Google creationTime lacks an offset; earliest plausible UTC freshness anchor."
                else:
                    basis = "Google creationTime includes an explicit timezone offset."
            else:
                values = [prefix for item in feed["values"] for prefix in item["properties"]["addressPrefixes"]]
                published = (
                    datetime.strptime(url.rsplit("_", 1)[1].removesuffix(".json"), "%Y%m%d").replace(
                        tzinfo=timezone.utc
                    )
                    - MAX_UTC_OFFSET
                )
                basis = "Azure filename publication date; earliest plausible UTC start-of-day freshness anchor."
            sources[provider] = {
                "url": url,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "published_at": published.isoformat(),
                "publication_basis": basis,
                "ranges": _collapse(values),
            }
        snapshot = {
            "schema": "vulnscanner.cloud-policy.v1",
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "sources": sources,
        }
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix="cloud-", dir=destination.parent)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(snapshot, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        policy = CloudRangePolicy.from_file(Path(temporary))
        policy.require_fresh()
        os.replace(temporary, destination)
        return policy
    except (OSError, URLError, UnicodeError, ValueError, TypeError, KeyError) as error:
        raise ScopeError("Policy refresh failed; the previous snapshot was preserved.") from error
    finally:
        if temporary and Path(temporary).exists():
            Path(temporary).unlink()


def main() -> int:
    """Separate CLI for fixed-publisher policy updates; never scans a target."""
    parser = argparse.ArgumentParser(description="Refresh the official cloud-range blocklist; does not scan targets.")
    parser.add_argument("--output", type=Path, default=Path("data/policy/cloud-ranges.json"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        policy = refresh_policy(args.output)
    except ScopeError as error:
        LOGGER.error("%s", error)
        return 1
    LOGGER.info(
        "Policy refreshed: %d collapsed ranges; captured %s", len(policy.networks), policy.captured_at.isoformat()
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
