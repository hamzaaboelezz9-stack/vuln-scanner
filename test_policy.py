"""Malformed/stale snapshots fail closed; publisher refreshes are atomic."""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scanner.safety.cloud_updates import AWS_FEED, AZURE_DOWNLOAD_PAGE, GOOGLE_FEED, refresh_policy
from scanner.safety.policy import CloudRangePolicy, ScopeError


def publisher_fixture() -> tuple[str, dict[str, bytes]]:
    """Return synthetic provider feeds, clearly separate from actual cloud ranges."""
    now = datetime.now(timezone.utc)
    azure = "https://download.microsoft.com/download/a/b/c/abc/ServiceTags_Public_" + now.strftime("%Y%m%d") + ".json"
    feeds = {
        AZURE_DOWNLOAD_PAGE: f'<a href="{azure}">Download</a>'.encode(),
        AWS_FEED: json.dumps(
            {
                "createDate": now.strftime("%Y-%m-%d-%H-%M-%S"),
                "prefixes": [{"ip_prefix": "34.0.0.0/8"}],
                "ipv6_prefixes": [],
            }
        ).encode(),
        GOOGLE_FEED: json.dumps({"creationTime": now.isoformat(), "prefixes": [{"ipv4Prefix": "35.0.0.0/8"}]}).encode(),
        azure: json.dumps({"values": [{"properties": {"addressPrefixes": ["20.0.0.0/8"]}}]}).encode(),
    }
    return azure, feeds


def test_policy_refresh_metadata_and_atomic_failure(tmp_path: Path) -> None:
    """Record actual source-byte hashes and retain old policy if a feed fails."""
    _, feeds = publisher_fixture()
    destination = tmp_path / "cloud.json"
    policy = refresh_policy(destination, fetch=feeds.__getitem__)
    policy.require_fresh()
    data = json.loads(destination.read_text())
    assert data["sources"]["aws"]["sha256"] == hashlib.sha256(feeds[AWS_FEED]).hexdigest()
    previous = destination.read_bytes()

    def failed(url: str) -> bytes:
        raise OSError("Simulated publisher outage.")

    with pytest.raises(ScopeError):
        refresh_policy(destination, fetch=failed)
    assert destination.read_bytes() == previous
    assert list(tmp_path.glob("cloud-*")) == []


@pytest.mark.parametrize(
    "mutation", ["missing-provider", "wrong-source", "empty-ranges", "default-route", "bad-time", "bad-digest"]
)
def test_invalid_policy_schema(tmp_path: Path, mutation: str) -> None:
    """Reject incomplete, malformed and nonpublisher snapshots."""
    _, feeds = publisher_fixture()
    destination = tmp_path / "cloud.json"
    refresh_policy(destination, fetch=feeds.__getitem__)
    data = json.loads(destination.read_text())
    if mutation == "missing-provider":
        del data["sources"]["azure"]
    elif mutation == "wrong-source":
        data["sources"]["aws"]["url"] = "https://example.com/policy.json"
    elif mutation == "empty-ranges":
        data["sources"]["google"]["ranges"] = []
    elif mutation == "default-route":
        data["sources"]["aws"]["ranges"] = ["0.0.0.0/0"]
    elif mutation == "bad-time":
        data["captured_at"] = "2026-10-06T12:00:00"
    else:
        data["sources"]["azure"]["sha256"] = "not-a-hash"
    destination.write_text(json.dumps(data))
    with pytest.raises(ScopeError):
        CloudRangePolicy.from_file(destination)


def test_future_and_old_publisher_dates(tmp_path: Path) -> None:
    """Recent downloads cannot make old or future provider data acceptable."""
    _, feeds = publisher_fixture()
    destination = tmp_path / "cloud.json"
    refresh_policy(destination, fetch=feeds.__getitem__)
    original = json.loads(destination.read_text())
    for offset in (timedelta(days=1), -timedelta(days=15)):
        data = json.loads(json.dumps(original))
        data["sources"]["aws"]["published_at"] = (datetime.now(timezone.utc) + offset).isoformat()
        destination.write_text(json.dumps(data))
        with pytest.raises(ScopeError):
            CloudRangePolicy.from_file(destination).require_fresh()


def test_refresh_rejects_official_feed_default_route(tmp_path: Path) -> None:
    """Never turn a malformed publisher feed into an overbroad blocklist."""
    _, feeds = publisher_fixture()
    feeds[AWS_FEED] = json.dumps(
        {
            "createDate": datetime.now(timezone.utc).strftime("%Y-%m-%d-%H-%M-%S"),
            "prefixes": [{"ip_prefix": "0.0.0.0/0"}],
            "ipv6_prefixes": [],
        }
    ).encode()
    destination = tmp_path / "cloud.json"
    with pytest.raises(ScopeError):
        refresh_policy(destination, fetch=feeds.__getitem__)
    assert not destination.exists()


def test_ambiguous_publisher_time_uses_conservative_anchor(tmp_path: Path) -> None:
    """Do not claim a timezone-less Google creationTime is UTC."""
    _, feeds = publisher_fixture()
    naive = datetime.now(timezone.utc).replace(tzinfo=None)
    feeds[GOOGLE_FEED] = json.dumps(
        {"creationTime": naive.isoformat(), "prefixes": [{"ipv4Prefix": "35.0.0.0/8"}]}
    ).encode()
    destination = tmp_path / "cloud.json"
    refresh_policy(destination, fetch=feeds.__getitem__)
    data = json.loads(destination.read_text())
    anchor = datetime.fromisoformat(data["sources"]["google"]["published_at"])
    assert anchor == naive.replace(tzinfo=timezone.utc) - timedelta(hours=14)
