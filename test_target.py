"""Parsing tests prevent URL/IP ambiguities before resolution."""

import pytest

from scanner.core.target import Target, TargetError


@pytest.mark.parametrize(
    "value",
    [
        "http://2130706433",
        "http://127.1",
        "http://0177.0.0.1",
        "http://0x7f000001",
        "http://127.00.0.1",
        "http://user:password@localhost",
        "http://localhost:0",
        "http://localhost:",
        "http://localhost:65536",
        "http://localhost/#fragment",
        "file:///etc/passwd",
        "http://localhost\\@example.com",
        "\nhttp://localhost",
        "http://local\thost",
        "http://[fe80::1%25eth0]",
        "http://%31%32%37.0.0.1",
        "https://..",
        "https://-bad.local",
        "https://bad..local",
        "localhost:3000",
    ],
)
def test_ambiguous_targets_are_rejected(value: str) -> None:
    """Each rejected form has a known parser or resolver ambiguity."""
    with pytest.raises(TargetError):
        Target.web(value)


def test_normalization_and_audit_identifier() -> None:
    """Normalize host case, IDNA and ports without persisting secret query values."""
    target = Target.web("HTTPS://BÜCHER.LOCAL.:443/login?token=private")
    assert target.hostname == "xn--bcher-kva.local"
    assert target.origin == ("https", "xn--bcher-kva.local", 443)
    assert target.url == "https://xn--bcher-kva.local/login?token=private"
    assert "private" not in target.display and "login" not in target.display
    assert "private" not in repr(target)
    assert Target.web("http://[::1]:3000").url == "http://[::1]:3000/"


def test_cidr_requires_network_alignment() -> None:
    """Reject silent widening from a host address to an entire network."""
    with pytest.raises(TargetError):
        Target.net("192.168.1.25/24")
    assert str(Target.net("192.168.1.0/24").network) == "192.168.1.0/24"
