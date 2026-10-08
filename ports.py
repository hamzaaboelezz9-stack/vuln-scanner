"""Strict port specifications, curated presets and optional operator-owned frequency data."""

import json
import math
import re
from pathlib import Path

from scanner.core.target import validate_port
from scanner.utils.resources import read_resource

MAX_SELECTED_PORTS = 1000
MAX_SPEC_BYTES = 8192
MAX_SERVICE_DATABASE_BYTES = 4 * 1024 * 1024
MAX_DATABASE_LINES = 50000
PRESETS = {"common100": 100, "common1000": 1000, "top100": 100, "top1000": 1000}


def frequency_ports(path: Path, count: int) -> tuple[int, ...]:
    """Rank TCP frequency records from an explicitly supplied nmap-services-style file."""
    with path.open("rb") as source:
        data = source.read(MAX_SERVICE_DATABASE_BYTES + 1)
    if len(data) > MAX_SERVICE_DATABASE_BYTES or count not in {100, 1000}:
        raise ValueError("Invalid frequency database or requested preset.")
    lines = data.decode("utf-8").splitlines()
    if len(lines) > MAX_DATABASE_LINES:
        raise ValueError("Frequency database exceeds its line cap.")
    frequencies: dict[int, float] = {}
    for line in lines:
        parts = line.split("#", 1)[0].split()
        if len(parts) < 3 or not re.fullmatch(r"[0-9]{1,5}/tcp", parts[1]):
            continue
        port = validate_port(int(parts[1].split("/")[0]))
        value = float(parts[2])
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("Invalid TCP frequency entry.")
        frequencies[port] = max(value, frequencies.get(port, 0))
    if len(frequencies) < count:
        raise ValueError("Frequency database has insufficient distinct TCP ports.")
    return tuple(sorted(frequencies, key=lambda p: (-frequencies[p], p))[:count])


def parse_ports(specification: str, database: Path | None = None) -> tuple[int, ...]:
    """Parse at most 1000 exact ports/ranges; top aliases disclose a curated fallback."""
    if not isinstance(specification, str) or not 1 <= len(specification) <= MAX_SPEC_BYTES:
        raise ValueError("Port specification length is invalid.")
    if specification in PRESETS:
        count = PRESETS[specification]
        if specification.startswith("top") and database is not None:
            return frequency_ports(database, count)
        data = json.loads(read_resource("ports/common.json", MAX_SPEC_BYTES * 2))
        ports = data["common" + str(count)]
        if data["schema"] != "vulnscanner.port-presets.v1" or len(ports) != count or len(set(ports)) != count:
            raise ValueError("Invalid built-in port preset.")
        return tuple(validate_port(port) for port in ports)
    if database is not None:
        raise ValueError("A frequency database applies only to top100/top1000.")
    result: list[int] = []
    for part in specification.split(","):
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", part):
            raise ValueError("Use exact comma-separated ports, ascending ranges or a named preset.")
        ends = [validate_port(int(value)) for value in part.split("-")]
        start, end = ends[0], ends[-1]
        if start > end or end - start + 1 > MAX_SELECTED_PORTS:
            raise ValueError("Port range exceeds the supported bounded selection.")
        for port in range(start, end + 1):
            if port in result:
                raise ValueError("Port selections must not overlap or repeat.")
            result.append(port)
            if len(result) > MAX_SELECTED_PORTS:
                raise ValueError("Select no more than 1000 distinct TCP ports.")
    return tuple(result)
