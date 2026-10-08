"""Conservative private-file GET refusal beneath discovery and input checks."""

import posixpath
from urllib.parse import parse_qsl, unquote, urlsplit

from scanner.safety.policy import ScopeError

PRIVATE_SEGMENTS = frozenset({".git", ".hg", ".svn"})
PRIVATE_BASENAMES = frozenset(
    {"config.json", "settings.json", "settings.py", "web.config", "docker-compose.yml", "docker-compose.yaml"}
)
PRIVATE_SUFFIXES = (
    ".map",
    ".sql",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".bak",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".yaml",
    ".yml",
    ".config",
)
FILE_QUERY_FIELDS = frozenset({"file", "path", "filename", "document", "template", "download"})
MAX_QUERY_FIELDS = 64
MAX_DECODE_ROUNDS = 3


def private_file_path(value: str) -> bool:
    """Recognize obvious config/repository/backup/OS-file targets, including encoded forms."""
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    value = value.lower().replace("\\", "/")
    parts = value.split("/")
    basename = posixpath.basename(value)
    return (
        any(part in PRIVATE_SEGMENTS or part.startswith(".env") for part in parts)
        or basename in PRIVATE_BASENAMES
        or basename.endswith(PRIVATE_SUFFIXES)
        or any(prefix in value for prefix in ("/etc/", "/proc/", "/sys/", "/root/", "/windows/", "c:/"))
    )


def reject_private_get(url: str) -> None:
    """Refuse known private-file GET routes; HEAD metadata remains available."""
    parsed = urlsplit(url)
    try:
        fields = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=MAX_QUERY_FIELDS)
    except ValueError as error:
        raise ScopeError("Query field cap prevents reliable safe-body classification.") from error
    if private_file_path(parsed.path) or any(
        name.lower() in FILE_QUERY_FIELDS and private_file_path(value) for name, value in fields
    ):
        raise ScopeError(
            "Private-file/source-map/OS-file GET is forbidden; metadata-only HEAD inspection is available."
        )
