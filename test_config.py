"""Reject configuration ambiguity before permission checks or target operations."""

from pathlib import Path

import pytest

from scanner.core.config import ConfigError, ScanConfig


@pytest.mark.parametrize(
    "settings",
    [
        {"workers": True},
        {"workers": 65},
        {"rate_limit": float("nan")},
        {"timeout": 0},
        {"scan_seconds": -1},
        {"max_hosts": 0},
        {"max_operations": False},
        {"max_redirects": 6},
        {"max_response_bytes": 1},
        {"respect_robots": "yes"},
        {"checks": ["headers", "headers"]},
        {"checks": []},
        {"user_agent": "anonymous"},
        {"user_agent": "VulnScanner/1.0 (authorized-testing-only)\r\nX: injected"},
    ],
)
def test_invalid_direct_settings(settings: dict[str, object]) -> None:
    """Direct Python construction must not bypass YAML validation."""
    with pytest.raises(ConfigError):
        ScanConfig(**settings)


@pytest.mark.parametrize(
    "content",
    [
        "workers: 2\nworkers: 3",
        "rate_limit: .nan",
        "i_have_permission: true",
        "base: &alias 1\nworkers: *alias",
        "!!python/object:builtins.object {}",
        "[workers, 3]",
        "1: 2",
        "workers: true",
        "<<: {}",
    ],
)
def test_unsafe_yaml_rejected(tmp_path: Path, content: str) -> None:
    """No unsafe constructors, permission grants, aliases or silently overwritten keys."""
    path = tmp_path / "config.yaml"
    path.write_text(content)
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_overrides_and_public_limits(tmp_path: Path) -> None:
    """Explicit overrides win without serializing private CA paths or supplied text."""
    path = tmp_path / "config.yaml"
    path.write_text("workers: 2\nchecks: [headers, cookies]\nca_bundle: /private/operator/ca.pem\n")
    config = ScanConfig.load(path, {"workers": 3})
    assert config.workers == 3 and config.checks == ("headers", "cookies")
    assert "ca_bundle" not in config.public_limits()
    assert "user_agent" not in config.public_limits()


def test_config_size_and_missing_file(tmp_path: Path) -> None:
    """Missing files and oversized inputs cannot silently fall back to defaults."""
    with pytest.raises(ConfigError):
        ScanConfig.load(tmp_path / "absent.yaml")
    path = tmp_path / "large.yaml"
    path.write_bytes(b"#" * 65537)
    with pytest.raises(ConfigError):
        ScanConfig.load(path)


def test_deep_yaml_large_number_and_invalid_path(tmp_path: Path) -> None:
    """Malformed local configuration remains a controlled error even at parser limits."""
    path = tmp_path / "nested.yaml"
    path.write_text("workers: " + "[" * 2000 + "1" + "]" * 2000)
    with pytest.raises(ConfigError):
        ScanConfig.load(path)
    with pytest.raises(ConfigError):
        ScanConfig(timeout=10**1000)
    with pytest.raises(ConfigError):
        ScanConfig(ca_bundle="invalid\x00path")
