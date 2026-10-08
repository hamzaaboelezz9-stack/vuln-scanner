"""Shared monotonic pacing; concurrency never increases the approved request rate."""

import math
import time
from threading import Lock
from typing import Callable

DEFAULT_RATE = 10.0
MIN_RATE = 0.1
MAX_RATE = 100.0
MAX_BACKOFF_SECONDS = 30.0
BACKOFF_BASE_SECONDS = 1.0
MAX_RETRIES = 3


class RateLimiter:
    """Strictly space operations without a token bucket's initial request burst."""

    def __init__(
        self,
        rate: float = DEFAULT_RATE,
        aggressive_permission: bool = False,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Require explicit aggressive-mode authorization for rates above ten."""
        if isinstance(rate, bool) or not math.isfinite(rate) or not MIN_RATE <= rate <= MAX_RATE:
            raise ValueError("Rate must be finite and between 0.1 and 100 operations/second.")
        if rate > DEFAULT_RATE and aggressive_permission is not True:
            raise PermissionError("Higher rates require --i-know-what-im-doing.")
        self._interval = 1.0 / rate
        self._clock, self._sleep = clock, sleep
        self._next = 0.0
        self._lock = Lock()

    def acquire(self) -> None:
        """Wait for one operation slot, rechecking after each sleep."""
        while True:
            with self._lock:
                now = self._clock()
                delay = self._next - now
                if delay <= 0:
                    self._next = now + self._interval
                    return
            self._sleep(delay)

    def defer(self, seconds: float) -> None:
        """Pause all workers after throttling or temporary server overload."""
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("Backoff must be finite and nonnegative.")
        with self._lock:
            self._next = max(self._next, self._clock() + min(seconds, MAX_BACKOFF_SECONDS))


def backoff_seconds(attempt: int) -> float:
    """Return bounded exponential delays; the HTTP session enforces a finite retry count."""
    if type(attempt) is not int or not 0 <= attempt < MAX_RETRIES:
        raise ValueError("Retry attempt is outside the permitted retry budget.")
    return min(BACKOFF_BASE_SECONDS * (2**attempt), MAX_BACKOFF_SECONDS)
