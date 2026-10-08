"""Atomic operation reservations, shared backoff and cooperative cancellation."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from scanner.core.config import ScanConfig
from scanner.core.errors import LimitReached
from scanner.safety.budget import ScanControl


def test_atomic_scan_budget_under_concurrency() -> None:
    """Forty racing workers cannot reserve more than the five approved attempts."""
    config = ScanConfig(max_operations=5, rate_limit=100)
    control = ScanControl(config, aggressive_permission=True)

    def reserve(_: int) -> bool:
        try:
            control.for_check(5).begin("TCP")
            return True
        except LimitReached:
            return False

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(reserve, range(40)))
    assert sum(results) == 5 and control.counts()["TCP"] == 5


def test_check_budget_cancellation_and_aggressive_flag() -> None:
    """Child limits, runtime flags and cancellation apply before new operations."""
    with pytest.raises(PermissionError):
        ScanControl(ScanConfig(rate_limit=11))
    control = ScanControl(ScanConfig())
    child = control.for_check(1)
    child.begin("TCP")
    with pytest.raises(LimitReached, match="Check operation"):
        child.begin("HTTP")
    assert child.used == 1
    control.cancel()
    with pytest.raises(LimitReached, match="cancelled"):
        control.for_check(1).begin("TCP")
    assert sum(control.counts().values()) == 1


def test_deadline_interrupts_shared_backoff() -> None:
    """A thirty-second server delay cannot outlive a one-second scan deadline."""
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    control = ScanControl(ScanConfig(scan_seconds=1), clock=lambda: clock[0], sleep=sleep)
    control.limiter.defer(30)
    with pytest.raises(LimitReached, match="deadline"):
        control.for_check(1).begin("HTTP")
    assert 1 <= clock[0] < 1.01


def test_invalid_budget_kind_and_size() -> None:
    """Internal misuse does not bypass accounting or introduce unbounded children."""
    control = ScanControl(ScanConfig())
    for maximum in (0, -1, True):
        with pytest.raises(ValueError):
            control.for_check(maximum)
    with pytest.raises(ValueError):
        control.for_check(1).begin("UNKNOWN")
