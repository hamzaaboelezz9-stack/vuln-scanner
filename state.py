"""Private authorization state and append-only JSON audit events."""

import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from uuid import UUID

from scanner.safety.policy import ScopeError, aware_time
from scanner.utils.evidence import safe_text

NOTICE_VERSION = "1"
PERMISSION_PHRASE = "I have permission"
MAX_STATE_BYTES = 4096
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
LEGAL_NOTICE = (
    "Only assess systems you own or have explicit authorization to test. "
    "Scanning can generate traffic, alerts and application logs. "
    "Scope restrictions do not establish ownership or replace written authorization. "
    'Type exactly "I have permission" to acknowledge this notice.'
)


class AuthorizationStore:
    """Persist acknowledgment and audit events in an owner-only state directory."""

    def __init__(self, directory: Path | None = None) -> None:
        """Reject symlinks and foreign-owned state; tighten existing permissions."""
        self.directory = directory or Path.home() / ".vulnscanner"
        self._lock = Lock()
        try:
            if self.directory.is_symlink():
                raise ScopeError("Authorization directory must not be a symlink.")
            self.directory.mkdir(mode=PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True)
            info = self.directory.stat()
            if not stat.S_ISDIR(info.st_mode) or (hasattr(os, "getuid") and info.st_uid != os.getuid()):
                raise ScopeError("Authorization directory has an invalid owner or type.")
            self.directory.chmod(PRIVATE_DIRECTORY_MODE)
        except OSError as error:
            raise ScopeError("Could not establish private authorization state.") from error

    def _open(self, name: str, flags: int) -> int:
        path = self.directory / name
        if path.is_symlink():
            raise ScopeError("Authorization files must not be symlinks.")
        descriptor = os.open(
            path, flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), PRIVATE_FILE_MODE
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            ):
                raise ScopeError("Authorization file has an invalid type, link count or owner.")
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, PRIVATE_FILE_MODE)
        except OSError:
            os.close(descriptor)
            raise
        return descriptor

    def acknowledged(self) -> bool:
        """Return false for absent state; reject corrupt state rather than ignoring it."""
        try:
            descriptor = self._open("acknowledgment.json", os.O_RDONLY)
        except FileNotFoundError:
            return False
        except OSError as error:
            raise ScopeError("Could not read authorization acknowledgment.") from error
        try:
            with os.fdopen(descriptor, "rb") as handle:
                payload = handle.read(MAX_STATE_BYTES + 1)
            if len(payload) > MAX_STATE_BYTES:
                raise ValueError("Acknowledgment is too large.")
            data = json.loads(payload)
            if data["notice_version"] != NOTICE_VERSION:
                return False
            if data["phrase"] != PERMISSION_PHRASE:
                raise ValueError("Invalid acknowledgment phrase.")
            at = aware_time(data["acknowledged_at"])
            if at > datetime.now(timezone.utc):
                raise ValueError("Future acknowledgment timestamp.")
            return True
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise ScopeError("Authorization acknowledgment is corrupt.") from error

    def acknowledge(self, phrase: str) -> None:
        """Save the exact legal acknowledgment atomically; no case/space folding."""
        if phrase != PERMISSION_PHRASE:
            raise ScopeError("The exact permission acknowledgment is required.")
        with self._lock:
            if self.acknowledged():
                return
            data = {
                "notice_version": NOTICE_VERSION,
                "phrase": phrase,
                "acknowledged_at": datetime.now(timezone.utc).isoformat(),
            }
            temporary: str | None = None
            try:
                descriptor, temporary = tempfile.mkstemp(prefix="ack-", dir=self.directory)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(data, handle)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.directory / "acknowledgment.json")
            except OSError as error:
                raise ScopeError("Could not persist authorization acknowledgment.") from error
            finally:
                if temporary and Path(temporary).exists():
                    Path(temporary).unlink()

    def record(
        self, scan_id: UUID, target: str, decision: str, public_permission: bool, acknowledged: bool, reason: str = ""
    ) -> None:
        """Append one bounded event; an unwritable audit log blocks authorization."""
        if decision not in {"approved", "blocked"}:
            raise ValueError("Invalid authorization decision.")
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": str(scan_id),
            "target": safe_text(target),
            "decision": decision,
            "notice_acknowledged": acknowledged,
            "public_permission": public_permission,
            "reason": safe_text(reason),
        }
        payload = (json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(payload) > MAX_STATE_BYTES:
            raise ScopeError("Audit event exceeds its size budget.")
        try:
            with self._lock:
                descriptor = self._open("scans.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND)
                with os.fdopen(descriptor, "ab", buffering=0) as handle:
                    if handle.write(payload) != len(payload):
                        raise OSError("Incomplete audit write.")
                    os.fsync(handle.fileno())
        except OSError as error:
            raise ScopeError("Audit log is unavailable; authorization is blocked.") from error
