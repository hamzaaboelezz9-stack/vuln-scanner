"""Small trusted path lists packaged with the wheel; no arbitrary payload loading."""

from pathlib import Path

from scanner.utils.resources import resource_path

MAX_WORDLIST_BYTES = 8192
MAX_WORDLIST_ENTRIES = 24
WORDLISTS = frozenset({"sensitive_files.txt", "common_dirs.txt", "xss_payloads.txt"})


def wordlist_path(name: str) -> Path:
    """Use source-tree data or the standard installed-wheel shared-data directory."""
    if name not in WORDLISTS:
        raise ValueError("Unknown built-in wordlist.")
    return resource_path("wordlists/" + name)


def load_wordlist(name: str) -> tuple[str, ...]:
    """Read bounded UTF-8 entries; path lists forbid queries, encodings and traversal."""
    with wordlist_path(name).open("rb") as source:
        raw = source.read(MAX_WORDLIST_BYTES + 1)
    if len(raw) > MAX_WORDLIST_BYTES:
        raise ValueError("Built-in wordlist exceeds its byte cap.")
    entries = tuple(
        line.strip() for line in raw.decode("utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")
    )
    if not entries or len(entries) > MAX_WORDLIST_ENTRIES or len(set(entries)) != len(entries):
        raise ValueError("Built-in wordlist is empty, oversized or duplicated.")
    if name != "xss_payloads.txt" and any(
        not value.startswith("/")
        or value.startswith("//")
        or ".." in value
        or any(char in value for char in "%?&#\\:")
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
        for value in entries
    ):
        raise ValueError("Built-in paths must be canonical local paths without traversal or queries.")
    return entries
