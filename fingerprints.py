"""Conservative passive protocol/product fingerprints; no active service commands."""

import json
import re
from functools import lru_cache

from scanner.core.network import MAX_NETWORK_BANNER, ServiceIdentity
from scanner.utils.resources import read_resource

MAX_FINGERPRINT_BYTES = 16 * 1024
MAX_SIGNATURES = 16
MAX_GREETING_TEXT = 1024


@lru_cache(maxsize=1)
def signatures() -> tuple[tuple[dict[str, str], re.Pattern[str]], ...]:
    """Compile only trusted bounded built-in signatures, never target-supplied regex."""
    data = json.loads(read_resource("fingerprints/services.json", MAX_FINGERPRINT_BYTES))
    items = data["signatures"]
    if data["schema"] != "vulnscanner.fingerprints.v1" or not 1 <= len(items) <= MAX_SIGNATURES:
        raise ValueError("Invalid fingerprint resource.")
    result = []
    for item in items:
        if set(item) - {"protocol", "product", "pattern", "vendor", "cpe_product"} or len(item["pattern"]) > 256:
            raise ValueError("Invalid built-in fingerprint.")
        ServiceIdentity(item["protocol"], item["product"])
        if ("vendor" in item) != ("cpe_product" in item):
            raise ValueError("Incomplete fingerprint CPE mapping.")
        result.append((item, re.compile(item["pattern"], re.I)))
    return tuple(result)


def fingerprint(banner: bytes) -> ServiceIdentity | None:
    """Extract constrained advertised identifiers; never use a port number as identity."""
    if not isinstance(banner, bytes) or len(banner) > MAX_NETWORK_BANNER:
        raise ValueError("Invalid greeting bytes.")
    text = banner[:MAX_GREETING_TEXT].decode("ascii", errors="replace")
    for item, pattern in signatures():
        match = pattern.search(text)
        if match:
            version = match.group(1)
            cpe = None
            if "vendor" in item:
                cpe_version, update = version, "*"
                if item["product"] == "openssh":
                    portable = re.fullmatch(r"([0-9]+\.[0-9]+)(p[0-9]+)?", version)
                    if portable:
                        cpe_version, update = portable.group(1), portable.group(2) or "-"
                elif item["product"] == "proftpd" and version[-1].isalpha():
                    cpe_version, update = version[:-1], version[-1]
                cpe = f"cpe:2.3:a:{item['vendor']}:{item['cpe_product']}:{cpe_version}:{update}:*:*:*:*:*:*"
            return ServiceIdentity(item["protocol"], item["product"], version, cpe)
    if re.match(r"^SSH-(?:2\.0|1\.99)-[\x21-\x7e]{1,64}(?:[ \r\n]|$)", text):
        return ServiceIdentity("ssh")
    if re.match(r"^220[ -][^\r\n]{0,200}\b(?:ESMTP|SMTP)\b", text, re.I):
        return ServiceIdentity("smtp")
    if re.match(r"^220[ -][^\r\n]{0,200}\bFTP\b", text, re.I):
        return ServiceIdentity("ftp")
    if re.match(r"^\* OK(?:[ \[])", text, re.I):
        return ServiceIdentity("imap")
    if re.match(r"^\+OK(?:[ \r\n])", text, re.I):
        return ServiceIdentity("pop3")
    if re.fullmatch(r"RFB [0-9]{3}\.[0-9]{3}\r?\n", text):
        return ServiceIdentity("vnc")  # RFB version is a protocol version, not software/CPE.
    if len(banner) >= 6 and banner[3] == 0 and banner[4] == 10:
        declared = int.from_bytes(banner[:3], "little")
        version = banner[5:].split(b"\0", 1)[0]
        if (
            10 <= declared <= MAX_NETWORK_BANNER
            and len(banner) >= declared + 4
            and b"\0" in banner[5:]
            and re.fullmatch(rb"[0-9][A-Za-z0-9._-]{0,63}", version)
        ):
            return ServiceIdentity("mysql", "mysql-compatible", version.decode("ascii"))
    return None
