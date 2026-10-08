"""Deterministic state fixtures; transport tests use only ephemeral loopback servers."""

from datetime import datetime, timezone
from ipaddress import ip_network
from pathlib import Path

import pytest

from scanner.safety.policy import CloudRangePolicy
from scanner.safety.state import PERMISSION_PHRASE, AuthorizationStore


@pytest.fixture
def state(tmp_path: Path) -> AuthorizationStore:
    """Provide an acknowledged, isolated private authorization directory."""
    store = AuthorizationStore(tmp_path / "state")
    store.acknowledge(PERMISSION_PHRASE)
    return store


@pytest.fixture
def cloud() -> CloudRangePolicy:
    """Use synthetic policy ranges solely to exercise decision paths."""
    now = datetime.now(timezone.utc)
    return CloudRangePolicy(
        now, (now, now, now), (ip_network("34.0.0.0/8"), ip_network("20.0.0.0/8"), ip_network("35.0.0.0/8"))
    )
