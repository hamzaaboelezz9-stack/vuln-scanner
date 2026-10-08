"""Port preset provenance, strict selections and conservative passive identities."""

import json
from pathlib import Path

import pytest

from scanner.core.network import BannerState, PortObservation, PortState, ServiceIdentity, TCPProbe
from scanner.utils.fingerprints import fingerprint
from scanner.utils.ports import parse_ports
from scanner.utils.resources import resource_path


@pytest.mark.parametrize(
    "selection,count", [("common100", 100), ("common1000", 1000), ("top100", 100), ("top1000", 1000)]
)
def test_curated_presets_have_exact_distinct_valid_ports(selection: str, count: int) -> None:
    """The default lists disclose coverage curation, not unsupported popularity statistics."""
    ports = parse_ports(selection)
    assert len(ports) == len(set(ports)) == count
    assert {22, 80, 443, 3306, 5432, 6379, 27017} <= set(ports)
    data = json.loads(resource_path("ports/common.json").read_text())
    assert "Not a statistical popularity ranking" in data["basis"]


@pytest.mark.parametrize(
    "selection", ["", "0", "65536", "22,22", "25-22", "1-1001", "22,20-23", "80,", "--all", "1;2", "22, 443", "1-65535"]
)
def test_port_spec_rejects_ambiguous_overlapping_or_unbounded_input(selection: str) -> None:
    """A parse failure happens before scope approval or socket construction."""
    with pytest.raises(ValueError):
        parse_ports(selection)


def test_operator_frequency_database_not_fake_rank(tmp_path: Path) -> None:
    """Top aliases use measured frequencies only when the operator explicitly supplies them."""
    database = tmp_path / "nmap-services"
    database.write_text(
        "# Synthetic frequency data, not real Nmap measurements\n"
        + "\n".join(f"demo {p}/tcp {p / 1000}" for p in range(1, 101))
        + "\ndemo 53/udp 1.0\n"
    )
    assert parse_ports("top100", database) == tuple(range(100, 0, -1))
    with pytest.raises(ValueError):
        parse_ports("top1000", database)
    with pytest.raises(ValueError):
        parse_ports("22,443", database)
    database.write_text("demo 22/tcp nan")
    with pytest.raises(ValueError):
        parse_ports("top100", database)


@pytest.mark.parametrize(
    "banner,protocol,product,version",
    [
        (b"SSH-2.0-OpenSSH_9.8p1 Ubuntu-1\r\n", "ssh", "openssh", "9.8p1"),
        (b"SSH-2.0-dropbear_2024.85\r\n", "ssh", "dropbear", "2024.85"),
        (b"SSH-2.0-CustomSSH_1.0\r\n", "ssh", None, None),
        (b"220 (vsFTPd 3.0.5)\r\n", "ftp", "vsftpd", "3.0.5"),
        (b"220 ProFTPD 1.3.8b Server\r\n", "ftp", "proftpd", "1.3.8b"),
        (b"220 fixture ESMTP Exim 4.96\r\n", "smtp", "exim", "4.96"),
        (b"220 fixture ESMTP public\r\n", "smtp", None, None),
        (b"* OK [CAPABILITY IMAP4rev1] public\r\n", "imap", None, None),
        (b"+OK public greeting\r\n", "pop3", None, None),
        (b"RFB 003.008\n", "vnc", None, None),
    ],
)
def test_passive_fingerprints(banner: bytes, protocol: str, product: str | None, version: str | None) -> None:
    """Protocol revision is not software version, and distro suffixes never prove patch status."""
    identity = fingerprint(banner)
    assert identity and (identity.protocol, identity.product, identity.version) == (protocol, product, version)
    assert identity.to_dict()["identity_verified"] is False
    if product == "openssh":
        assert identity.cpe == "cpe:2.3:a:openbsd:openssh:9.8:p1:*:*:*:*:*:*"
    if product == "proftpd":
        assert identity.cpe == "cpe:2.3:a:proftpd:proftpd:1.3.8:b:*:*:*:*:*:*"


@pytest.mark.parametrize(
    "banner",
    [
        b"",
        b"220 ambiguous host\r\n",
        b"HTTP port unknown and no greeting",
        b"220 vsFTPd 1.1." + b"9" * 200 + b"\r\n",
        b"SSH-2.0-OpenSSH_9.8p99999\r\n",
    ],
)
def test_ambiguous_or_adversarial_greeting_never_raises_or_guesses_version(banner: bytes) -> None:
    """Unexpected greetings may remain unknown but cannot crash the whole survey."""
    identity = fingerprint(banner)
    assert identity is None or identity.version is None


def test_complete_mysql_compatible_greeting_has_no_vendor_cpe() -> None:
    """MySQL-compatible handshakes do not establish Oracle product or patch identity."""
    packet = b"\x0a8.0.33\0" + b"\0" * 30
    identity = fingerprint(len(packet).to_bytes(3, "little") + b"\0" + packet)
    assert identity and identity.protocol == "mysql" and identity.version == "8.0.33" and identity.cpe is None
    assert fingerprint(b"\xff\xff\x01\0\x0a8.0.33\0") is None


def test_incomplete_mysql_packet_does_not_establish_a_service_identity() -> None:
    """A readable version prefix cannot replace the complete declared handshake."""
    truncated = b"\x0a8.0.33\0"
    assert fingerprint((100).to_bytes(3, "little") + b"\0" + truncated) is None


def test_network_models_reject_impossible_records_and_resource_paths() -> None:
    """All raw greetings are hidden from repr; unsafe identities and paths are rejected."""
    with pytest.raises(ValueError):
        TCPProbe("127.0.0.1", 22, PortState.REFUSED, banner=b"secret")
    with pytest.raises(ValueError):
        ServiceIdentity("ssh", "openssh", "9.8;secret")
    with pytest.raises(ValueError):
        ServiceIdentity("ssh", "", "9.8")
    with pytest.raises(ValueError):
        PortObservation("127.0.0.1", 22, PortState.TIMEOUT, BannerState.NOT_READ, ServiceIdentity("ssh"))
    with pytest.raises(ValueError):
        resource_path("../../private")
