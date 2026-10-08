"""Shared cancellation, monotonic deadlines and atomic per-check/scan budgets."""

import time
from threading import Event, Lock
from typing import Callable

from scanner.core.config import ScanConfig
from scanner.core.errors import LimitReached
from scanner.safety.rate_limit import RateLimiter

WAIT_SLICE_SECONDS = 0.1
OPERATION_KINDS = frozenset({"HTTP", "TCP", "TLS"})


class ScanControl:
    """One scan-wide limiter and operation ledger shared by all check workers."""

    def __init__(
        self,
        config: ScanConfig,
        aggressive_permission: bool = False,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Create a deadline and cancellable pacing; tests may supply virtual time."""
        if type(aggressive_permission) is not bool:
            raise ValueError("Aggressive permission must be an explicit boolean.")
        self.config, self.aggressive_permission = config, aggressive_permission
        self._clock = clock
        self._deadline = clock() + config.scan_seconds
        self._maximum = config.max_operations
        self._cancelled = Event()
        self._lock = Lock()
        self._counts = dict.fromkeys(sorted(OPERATION_KINDS), 0)
        self._claimed = False
        self._sleep = sleep
        self.limiter = RateLimiter(config.rate_limit, aggressive_permission, clock, self._wait)

    def _wait(self, seconds: float) -> None:
        remaining = seconds
        while remaining > 0:
            self.checkpoint()
            interval = min(remaining, WAIT_SLICE_SECONDS, self.remaining())
            if self._sleep is None:
                self._cancelled.wait(interval)
            else:
                self._sleep(interval)
            remaining -= interval
        self.checkpoint()

    def checkpoint(self) -> None:
        """Stop before further network work after cancellation or deadline expiry."""
        if self._cancelled.is_set():
            raise LimitReached("Scan was cancelled.")
        if self._clock() >= self._deadline:
            raise LimitReached("Scan deadline reached.")

    def claim(self) -> None:
        """Prevent accidental reuse of one controller across separate scan identifiers."""
        with self._lock:
            if self._claimed:
                raise ValueError("A scan controller may be used by only one engine invocation.")
            self._claimed = True

    def remaining(self) -> float:
        """Return a positive timeout bounded by the scan's remaining lifetime."""
        self.checkpoint()
        remaining = self._deadline - self._clock()
        if remaining <= 0:
            raise LimitReached("Scan deadline reached.")
        return remaining

    def cancel(self) -> None:
        """Signal all cooperative transports to stop starting operations."""
        self._cancelled.set()

    def for_check(self, maximum: int) -> "CheckBudget":
        """Create a child budget that cannot bypass scan-wide accounting."""
        if type(maximum) is not int or maximum < 1:
            raise ValueError("Check operation budgets must be positive integers.")
        return CheckBudget(self, min(maximum, self._maximum))

    def counts(self) -> dict[str, int]:
        """Snapshot reserved attempts, including failed connections and retries."""
        with self._lock:
            return dict(self._counts)


class CheckBudget:
    """A child ledger; reservations update both counters under the same lock."""

    def __init__(self, control: ScanControl, maximum: int) -> None:
        """Bind the check to its parent controller and declared operation cap."""
        self.control = control
        self.maximum = maximum
        self._used = 0

    def begin(self, kind: str) -> None:
        """Reserve and pace one attempt; redirects and retries reserve new slots."""
        if kind not in OPERATION_KINDS:
            raise ValueError("Unknown transport operation kind.")
        self.control.checkpoint()
        with self.control._lock:
            if self._used >= self.maximum:
                raise LimitReached("Check operation budget reached.")
            if sum(self.control._counts.values()) >= self.control._maximum:
                raise LimitReached("Scan operation budget reached.")
            self._used += 1
            self.control._counts[kind] += 1
        self.control.limiter.acquire()
        self.control.checkpoint()

    @property
    def used(self) -> int:
        """Read the reserved operation count safely from another thread."""
        with self.control._lock:
            return self._used
