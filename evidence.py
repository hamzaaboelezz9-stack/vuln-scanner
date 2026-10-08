"""Bound evidence and remove common secret-bearing fields before persistence."""

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MAX_EVIDENCE_LENGTH = 2048
MAX_QUERY_FIELDS = 64
SECRET_ASSIGNMENT = re.compile(
    r"(?im)\b(password|passwd|secret|token|api[_-]?key|authorization|cookie|set-cookie)"
    r"\b([\"']?\s*[:=]\s*)([^\r\n,;<>]+)"
)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def redact_url(value: str) -> str:
    """Remove URL userinfo and every query value; retain parameter names."""
    try:
        parsed = urlsplit(value)
        if not parsed.hostname:
            return "[invalid URL]"
        host = parsed.hostname
        host = f"[{host}]" if ":" in host else host
        if parsed.port:
            host += f":{parsed.port}"
        query = urlencode(
            [
                (key, "[redacted]")
                for key, _ in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=MAX_QUERY_FIELDS)
            ]
        )
        return urlunsplit((parsed.scheme, host, parsed.path, query, ""))
    except ValueError:
        return "[invalid URL]"


def safe_text(value: str, limit: int = MAX_EVIDENCE_LENGTH) -> str:
    """Redact common tokens and neutralize terminal/log control characters.

    This is a secondary safeguard, not a universal secret detector. Checks must
    construct minimal observations rather than submitting entire response bodies.
    """
    if not isinstance(value, str):
        raise TypeError("Evidence must be text.")
    if type(limit) is not int or not 1 <= limit <= MAX_EVIDENCE_LENGTH:
        raise ValueError("Invalid evidence length limit.")
    text = value[: limit * 2]
    text = URL_PATTERN.sub(lambda match: redact_url(match.group()), text)
    text = SECRET_ASSIGNMENT.sub(r"\1\2[redacted]", text)
    text = JWT_PATTERN.sub("[redacted JWT]", text)
    text = "".join(char if char in "\n\t" or (ord(char) >= 32 and ord(char) != 127) else " " for char in text)
    return text[:limit]
