"""Scope checks use synthetic DNS only; no targets are scanned."""

import json
import os
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Callable
from uuid import UUID

import pytest

from scanner.core.target import Target
from scanner.safety.authorization import ScopeGate
from scanner.safety.policy import Allowlist, CloudRangePolicy, ScopeError
from scanner.safety.resolver import Resolution
from scanner.safety.state import PERMISSION_PHRASE, AuthorizationStore


def fixed(*addresses: str, aliases: tuple[str, ...] = ()) -> Callable[[str], Resolution]:
    """Return a deterministic resolver, with no DNS or socket operations."""

    def resolve(host: str) -> Resolution:
        return Resolution(tuple(addresses), aliases)

    return resolve


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.2"])
def test_default_local_ranges(state: AuthorizationStore, address: str) -> None:
    """Allow precisely the default local address families and boundaries."""
    scope = ScopeGate(state, resolver=fixed(address)).authorize(Target.net(address), ports=(80,))
    assert scope.permit(address, 80).addresses == (address,)


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",
        "100.100.100.200",
        "0.0.0.0",
        "224.0.0.1",
        "192.0.2.1",
        "fe80::1",
        "2001:db8::1",
        "64:ff9b::a9fe:a9fe",
        "2002:a9fe:a9fe::1",
        "fd00:ec2::254",
        "fd20:ce::254",
    ],
)
def test_hard_blocks_override_allowlist(state: AuthorizationStore, cloud: CloudRangePolicy, address: str) -> None:
    """Metadata and translated/special addresses cannot be authorized by flags."""
    gate = ScopeGate(state, Allowlist.from_lines([address]), cloud, fixed(address))
    with pytest.raises(ScopeError):
        gate.authorize(Target.net(address), True, (80,))


@pytest.mark.parametrize("name", ["example.gov", "a.example.mil", "SERVICE.GOV.UK."])
def test_government_names_fail_before_dns(state: AuthorizationStore, cloud: CloudRangePolicy, name: str) -> None:
    """Hard-blocked names do not reach the resolver."""

    def unexpected(host: str) -> Resolution:
        raise AssertionError("DNS must not be queried.")

    with pytest.raises(ScopeError):
        ScopeGate(state, Allowlist.from_lines([name]), cloud, unexpected).authorize(Target.web(f"https://{name}"), True)


def test_public_requires_both_controls_and_fresh_policy(state: AuthorizationStore, cloud: CloudRangePolicy) -> None:
    """Neither saved acknowledgment nor either public-scope control is enough alone."""
    target = Target.net("8.8.8.8")
    allowed = Allowlist.from_lines(["8.8.8.8"])
    for allowlist, permission, policy in [(Allowlist(), True, cloud), (allowed, False, cloud), (allowed, True, None)]:
        with pytest.raises(ScopeError):
            ScopeGate(state, allowlist, policy, fixed("8.8.8.8")).authorize(target, permission, (443,))
    scope = ScopeGate(state, allowed, cloud, fixed("8.8.8.8")).authorize(target, True, (443,))
    assert scope.permit("8.8.8.8", 443).port == 443
    stale = replace(cloud, captured_at=cloud.captured_at - timedelta(days=8))
    with pytest.raises(ScopeError):
        ScopeGate(state, allowed, stale, fixed("8.8.8.8")).authorize(target, True, (443,))


def test_cloud_and_mapped_addresses_cannot_bypass_blocks(state: AuthorizationStore, cloud: CloudRangePolicy) -> None:
    """Normalize IPv4-mapped IPv6 before applying provider or metadata blocks."""
    for address in ("34.1.2.3", "::ffff:34.1.2.3", "::ffff:169.254.169.254"):
        with pytest.raises(ScopeError):
            ScopeGate(state, Allowlist.from_lines([address]), cloud, fixed(address)).authorize(
                Target.net(address), True, (80,)
            )


def test_dns_mixture_aliases_and_local_namespace(state: AuthorizationStore, cloud: CloudRangePolicy) -> None:
    """Reject the whole answer rather than selecting just its permitted address."""
    for addresses, aliases in [
        (("10.0.0.1", "169.254.169.254"), ()),
        (("10.0.0.1",), ("service.gov",)),
        (("8.8.8.8",), ()),
    ]:
        with pytest.raises(ScopeError):
            ScopeGate(state, cloud=cloud, resolver=fixed(*addresses, aliases=aliases)).authorize(
                Target.web("http://lab.local"), True
            )


def test_dns_is_pinned_and_redirect_origin_is_enforced(state: AuthorizationStore) -> None:
    """A changing resolver is called once; subsequent connections use approved IPs."""
    calls: list[str] = []

    def changing(host: str) -> Resolution:
        calls.append(host)
        return Resolution(("10.0.0.1",)) if len(calls) == 1 else Resolution(("169.254.169.254",))

    scope = ScopeGate(state, resolver=changing).authorize(Target.web("http://lab.local"))
    assert scope.permit("lab.local", 80, "http").addresses == ("10.0.0.1",)
    assert scope.permit("lab.local", 443, "https").addresses == ("10.0.0.1",)
    assert calls == ["lab.local"]
    for host, port, scheme in [("other.local", 80, "http"), ("lab.local", 22, "http"), ("lab.local", 443, "http")]:
        with pytest.raises(ScopeError):
            scope.permit(host, port, scheme)


def test_cidr_budget_membership_and_partial_public_allowlist(
    state: AuthorizationStore, cloud: CloudRangePolicy
) -> None:
    """Prevent unbounded expansion and an allowlisted first IP widening scope."""
    gate = ScopeGate(state)
    with pytest.raises(ScopeError):
        gate.authorize(Target.net("10.0.0.0/8"), ports=(80,))
    scope = gate.authorize(Target.net("192.168.1.0/30"), ports=(80,))
    assert scope.permit("192.168.1.1", 80).addresses == ("192.168.1.1",)
    with pytest.raises(ScopeError):
        scope.permit("192.168.1.4", 80)
    with pytest.raises(ScopeError):
        ScopeGate(state, Allowlist.from_lines(["8.8.8.0/32"]), cloud).authorize(Target.net("8.8.8.0/30"), True, (80,))


def test_acknowledgment_exactness_and_no_resolution_before_ack(tmp_path: Path) -> None:
    """The first-run gate cannot be bypassed by flags or a modified phrase."""
    store = AuthorizationStore(tmp_path / "state")
    for phrase in ("yes", "I have permission ", "i have permission"):
        with pytest.raises(ScopeError):
            store.acknowledge(phrase)

    def unexpected(host: str) -> Resolution:
        raise AssertionError("Resolution before acknowledgment.")

    with pytest.raises(ScopeError):
        ScopeGate(store, resolver=unexpected).authorize(Target.web("http://localhost"), True)
    store.acknowledge(PERMISSION_PHRASE)
    assert store.acknowledged()
    (store.directory / "acknowledgment.json").write_text(
        '{"notice_version":"1","phrase":"I have permission","acknowledged_at":42}'
    )
    with pytest.raises(ScopeError):
        store.acknowledged()


def test_audit_records_and_permissions(state: AuthorizationStore) -> None:
    """Persist traceable, query-free decisions and owner-only files on POSIX."""
    scope = ScopeGate(state).authorize(Target.web("http://localhost/login?password=secret"))
    with pytest.raises(ScopeError):
        ScopeGate(state).authorize(Target.web("http://service.gov"))
    payload = (state.directory / "scans.log").read_text()
    events = [json.loads(line) for line in payload.splitlines()]
    assert [event["decision"] for event in events] == ["approved", "blocked"]
    assert events[0]["scan_id"] == str(scope.scan_id)
    assert all(UUID(event["scan_id"]) for event in events)
    assert "secret" not in payload and "login" not in payload
    if os.name == "posix":
        assert state.directory.stat().st_mode & 0o777 == 0o700
        assert (state.directory / "scans.log").stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink/permission semantics")
def test_state_symlinks_and_unwritable_audit_fail_closed(state: AuthorizationStore, tmp_path: Path) -> None:
    """Do not follow authorization symlinks or scan without a durable audit event."""
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched")
    (state.directory / "scans.log").symlink_to(outside)
    with pytest.raises(ScopeError):
        ScopeGate(state).authorize(Target.web("http://localhost"))
    assert outside.read_text() == "untouched"
    directory_link = tmp_path / "state-link"
    directory_link.symlink_to(state.directory, target_is_directory=True)
    with pytest.raises(ScopeError):
        AuthorizationStore(directory_link)


@pytest.mark.parametrize(
    "entry",
    ["*.example.com", "https://example.com", "0.0.0.0/0", "::/0", "192.168.1.4/24", "127.1", "::ffff:192.168.1.0/120"],
)
def test_invalid_allowlist_entries(entry: str) -> None:
    """Reject wildcard and overbroad scope representations."""
    with pytest.raises(ScopeError):
        Allowlist.from_lines([entry])
