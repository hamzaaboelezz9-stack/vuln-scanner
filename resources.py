"""Bounded trusted resources available from source trees and standard wheel installs."""

import sysconfig
from pathlib import Path

RESOURCES = frozenset(
    {
        "policy/cloud-ranges.json",
        "ports/common.json",
        "fingerprints/services.json",
        "wordlists/sensitive_files.txt",
        "wordlists/common_dirs.txt",
        "wordlists/xss_payloads.txt",
    }
)


def resource_path(name: str) -> Path:
    """Resolve only enumerated built-in data; never accept arbitrary relative paths."""
    if name not in RESOURCES:
        raise ValueError("Unknown built-in resource.")
    source = Path(__file__).resolve().parents[2] / "data" / name
    return source if source.is_file() else Path(sysconfig.get_path("data")) / "share/vulnscanner" / name


def read_resource(name: str, maximum: int) -> bytes:
    """Read at most a caller-specified, bounded amount of trusted package data."""
    if type(maximum) is not int or not 1 <= maximum <= 1024 * 1024:
        raise ValueError("Invalid resource byte cap.")
    with resource_path(name).open("rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("Built-in resource exceeds its byte cap.")
    return data
