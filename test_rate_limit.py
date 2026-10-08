"""Shared pacing under simultaneous callers and deterministic backoff."""

import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock

import pytest

from scanner.safety.rate_limit import RateLimiter, backoff_seconds


@pytest.mark.parametrize("rate", [0, -1, float("nan"), float("inf"), True, 101, 1e-300])
def test_invalid_rates(rate: float) -> None:
    """Reject values that could disable pacing or overflow delay calculations."""
    with pytest.raises(ValueError):
        RateLimiter(rate)


def test_aggressive_permission_and_retry_budget() -> None:
    """Aggressive pacing requires an explicit flag; retries remain bounded."""
    with pytest.raises(PermissionError):
        RateLimiter(11)
    assert [backoff_seconds(attempt) for attempt in range(3)] == [1, 2, 4]
    with pytest.raises(ValueError):
        backoff_seconds(3)


def test_concurrent_callers_do_not_burst() -> None:
    """Eight workers still consume one globally spaced sequence of slots."""
    limiter = RateLimiter(50, aggressive_permission=True)
    barrier = Barrier(8)
    lock = Lock()
    times: list[float] = []

    def operation() -> None:
        barrier.wait()
        limiter.acquire()
        with lock:
            times.append(time.monotonic())

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: operation(), range(8)))
    ordered = sorted(times)
    assert ordered[-1] - ordered[0] >= 0.12


def test_backoff_delays_every_worker() -> None:
    """A server overload event extends the shared next-operation deadline."""
    clock = [1.0]
    delays: list[float] = []

    def sleep(delay: float) -> None:
        delays.append(delay)
        clock[0] += delay

    limiter = RateLimiter(clock=lambda: clock[0], sleep=sleep)
    limiter.defer(2)
    limiter.acquire()
    assert delays == [2]
