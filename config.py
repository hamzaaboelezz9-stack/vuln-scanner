"""Bounded YAML configuration with strict keys, types and no permission grants."""

import math
import re
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Mapping

import yaml

from scanner.safety.rate_limit import DEFAULT_RATE, MAX_RATE, MIN_RATE

DEFAULT_TIMEOUT = 10.0
DEFAULT_WORKERS = 10
DEFAULT_MAX_OPERATIONS = 5_000
DEFAULT_SCAN_SECONDS = 600.0
DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024
DEFAULT_USER_AGENT = "VulnScanner/1.0 (authorized-testing-only)"
MAX_CONFIG_BYTES = 64 * 1024
MAX_YAML_DEPTH = 8
MAX_WORKERS = 64
MAX_OPERATIONS = 200_000
MAX_SCAN_SECONDS = 3_600.0
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_REDIRECTS = 5
MAX_SELECTED_CHECKS = 64
MAX_USER_AGENT_BYTES = 256


class ConfigError(ValueError):
    """Configuration cannot safely describe a scan."""


class _StrictLoader(yaml.SafeLoader):
    """Safe scalar construction with duplicate-key detection."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[str, object]:
        """Reject duplicate, merge and non-string keys before construction."""
        mapping: dict[str, object] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key == "<<" or key in mapping:
                raise ConfigError("Configuration keys must be unique strings; YAML merges are unsupported.")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _integer(value: object, name: str, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be an integer between {minimum} and {maximum}.")


def _number(value: object, name: str, minimum: float, maximum: float) -> None:
    try:
        valid = type(value) in (int, float) and math.isfinite(value) and minimum <= value <= maximum
    except OverflowError:
        valid = False
    if not valid:
        raise ConfigError(f"{name} must be finite and between {minimum} and {maximum}.")


@dataclass(frozen=True)
class ScanConfig:
    """Non-secret operational settings; permission switches remain runtime-only."""

    workers: int = DEFAULT_WORKERS
    rate_limit: float = DEFAULT_RATE
    timeout: float = DEFAULT_TIMEOUT
    max_hosts: int = 256
    max_operations: int = DEFAULT_MAX_OPERATIONS
    scan_seconds: float = DEFAULT_SCAN_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    max_redirects: int = 3
    checks: tuple[str, ...] | None = None
    user_agent: str = DEFAULT_USER_AGENT
    ca_bundle: str | None = None
    respect_robots: bool = False
    tls_expiry_days: int = 30
    weak_tls_probes: bool = True
    network_banner_seconds: float = 0.5
    cve_cache: str | None = None
    traversal_canary_path: str | None = None
    traversal_canary_token: str | None = None

    def __post_init__(self) -> None:
        """Validate direct construction as strictly as YAML loading."""
        _integer(self.workers, "workers", 1, MAX_WORKERS)
        _number(self.network_banner_seconds, "network_banner_seconds", 0.05, 5.0)
        if self.cve_cache is not None and (
            not isinstance(self.cve_cache, str)
            or not self.cve_cache
            or len(self.cve_cache) > 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in self.cve_cache)
        ):
            raise ConfigError("cve_cache must be a local cache directory path.")
        _number(self.rate_limit, "rate_limit", MIN_RATE, MAX_RATE)
        _number(self.timeout, "timeout", 0.05, 60.0)
        _integer(self.max_hosts, "max_hosts", 1, 4096)
        _integer(self.max_operations, "max_operations", 1, MAX_OPERATIONS)
        _number(self.scan_seconds, "scan_seconds", 0.05, MAX_SCAN_SECONDS)
        _integer(self.max_response_bytes, "max_response_bytes", 256, MAX_RESPONSE_BYTES)
        _integer(self.max_redirects, "max_redirects", 0, MAX_REDIRECTS)
        if type(self.respect_robots) is not bool:
            raise ConfigError("respect_robots must be a boolean.")
        _integer(self.tls_expiry_days, "tls_expiry_days", 1, 365)
        if type(self.weak_tls_probes) is not bool:
            raise ConfigError("weak_tls_probes must be a boolean.")
        if (self.traversal_canary_path is None) != (self.traversal_canary_token is None):
            raise ConfigError("Traversal requires both public canary path and token.")
        if self.traversal_canary_path is not None and (
            not isinstance(self.traversal_canary_path, str)
            or not re.fullmatch(r"/vulnscanner-canary-[a-f0-9]{16,64}\.txt", self.traversal_canary_path)
            or not isinstance(self.traversal_canary_token, str)
            or not re.fullmatch(r"vulnscanner-canary-[A-Za-z0-9_-]{16,96}", self.traversal_canary_token)
        ):
            raise ConfigError("Traversal accepts only an explicitly named public, non-secret scanner canary.")
        if (
            not isinstance(self.user_agent, str)
            or not 1 <= len(self.user_agent) <= MAX_USER_AGENT_BYTES
            or not self.user_agent.isascii()
            or any(ord(character) < 32 or ord(character) == 127 for character in self.user_agent)
            or "VulnScanner/" not in self.user_agent
            or "authorized-testing-only" not in self.user_agent
        ):
            raise ConfigError("user_agent must retain VulnScanner identification and the authorized-testing-only tag.")
        if self.ca_bundle is not None and (
            not isinstance(self.ca_bundle, str)
            or not self.ca_bundle
            or len(self.ca_bundle) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in self.ca_bundle)
        ):
            raise ConfigError("ca_bundle must be a local certificate-bundle path.")
        if self.checks is not None:
            if (
                not isinstance(self.checks, (tuple, list))
                or not 1 <= len(self.checks) <= MAX_SELECTED_CHECKS
                or any(
                    not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,31}", name) for name in self.checks
                )
                or len(set(self.checks)) != len(self.checks)
            ):
                raise ConfigError("checks must contain distinct registered check names.")
            object.__setattr__(self, "checks", tuple(self.checks))

    @classmethod
    def load(cls, path: Path | None = None, overrides: Mapping[str, object] | None = None) -> "ScanConfig":
        """Apply explicit overrides after bounded YAML; reject unknown fields."""
        values: dict[str, object] = {}
        if path is not None:
            try:
                with path.open("rb") as source:
                    raw = source.read(MAX_CONFIG_BYTES + 1)
                if len(raw) > MAX_CONFIG_BYTES:
                    raise ConfigError("Configuration exceeds 64 KiB.")
                text = raw.decode("utf-8")
                depth = 0
                for token in yaml.scan(text):
                    if isinstance(token, (yaml.AliasToken, yaml.AnchorToken)):
                        raise ConfigError("YAML aliases and anchors are unsupported.")
                    if isinstance(
                        token,
                        (
                            yaml.BlockMappingStartToken,
                            yaml.BlockSequenceStartToken,
                            yaml.FlowMappingStartToken,
                            yaml.FlowSequenceStartToken,
                        ),
                    ):
                        depth += 1
                        if depth > MAX_YAML_DEPTH:
                            raise ConfigError("YAML nesting exceeds the permitted depth.")
                    elif isinstance(token, (yaml.BlockEndToken, yaml.FlowMappingEndToken, yaml.FlowSequenceEndToken)):
                        depth -= 1
                document = yaml.load(text, Loader=_StrictLoader)
            except ConfigError:
                raise
            except (OSError, UnicodeError, yaml.YAMLError, RecursionError, ValueError) as error:
                raise ConfigError("Configuration could not be read as safe UTF-8 YAML.") from error
            if document is not None and not isinstance(document, dict):
                raise ConfigError("Configuration must be a mapping.")
            values.update(document or {})
        if overrides is not None:
            values.update(overrides)
        valid_keys = {item.name for item in fields(cls)}
        if set(values) - valid_keys:
            raise ConfigError("Configuration includes unknown settings or permission flags.")
        return cls(**values)

    def public_limits(self) -> dict[str, object]:
        """Export operational limits without local paths or operator-supplied text."""
        values = asdict(self)
        return {
            key: value
            for key, value in values.items()
            if key
            not in {"ca_bundle", "user_agent", "checks", "cve_cache", "traversal_canary_path", "traversal_canary_token"}
        }
