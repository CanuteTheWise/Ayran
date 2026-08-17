"""Strict, provenance-tracked configuration loading with monotonic narrowing.

Blueprint §16 fixes precedence as:
``defaults < global < project < engagement < allowlisted env < explicit CLI``.

This loader is fail-closed for security-relevant keys: a later layer may only
narrow permitted scope/budgets/capabilities; it may never weaken a mandatory
evidence, sandbox, provenance, redaction, schema, or human-approval rule unless
the run operator has passed an explicit ``security_override_allowed=true`` flag
in the *private global* layer only.  Unknown keys, type mismatches, and any
attempt to weaken a monotonic key raise :class:`ConfigError`.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from .models import EffectiveConfig, LoadSource


class ConfigError(ValueError):
    """Raised for malformed, unknown, or policy-violating configuration input."""

    def __init__(self, code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
        self.code = code
        self.details = details or {}
        super().__init__(message)


# Security-sensitive keys that may only move in the narrowing direction.
# direction: "min" (lower is safer), "max" (higher is safer), or "bool_true"/"bool_false"
# (policy may only be weakened by explicit override).
_MONOTONIC: dict[str, tuple[str, Any]] = {
    "journal_fsync": ("bool_true", True),
    "security_override_allowed": ("bool_false", False),
    "allow_install": ("bool_false", False),
    "max_parallel_external_tools": ("min", 2),
    "max_parallel_models": ("min", 2),
    "max_rss_mib": ("min", 4096),
    "min_free_disk_mib": ("max", 4096),
    "default_wall_minutes": ("min", 240),
    "no_progress_minutes": ("min", 20),
    "graceful_stop_seconds": ("min", 20),
    "sqlite_busy_timeout_ms": ("min", 5000),
    "snapshot_every_events": ("min", 10000),
    "require_pinned_rpc_block": ("bool_true", True),
    "offline": ("bool_false", False),
}

_ALLOWED_TOP_LEVEL: dict[str, tuple[type, ...]] = {
    "schema_version": (int,),
    "state_root": (str,),
    "cache_root": (str,),
    "config_root": (str,),
    "service_socket_name": (str,),
    "journal_fsync": (bool,),
    "sqlite_busy_timeout_ms": (int,),
    "snapshot_every_events": (int,),
    "security_override_allowed": (bool,),
    "allow_install": (bool,),
    "log_level": (str,),
    "offline": (bool,),
    "max_parallel_external_tools": (int,),
    "max_parallel_models": (int,),
    "max_rss_mib": (int,),
    "min_free_disk_mib": (int,),
    "default_wall_minutes": (int,),
    "no_progress_minutes": (int,),
    "graceful_stop_seconds": (int,),
    "network_default": (str,),
    "allowed_network_classes": (list,),
    "require_pinned_rpc_block": (bool,),
    "tools": (dict,),
}

_ALLOWED_NETWORK_DEFAULTS = {"deny", "allow_classes"}
_ALLOWED_ENV_KEYS = {
    "AYRAN_CONFIG": ("str", None),
    "AYRAN_STATE_ROOT": ("str", "state_root"),
    "AYRAN_LOG_LEVEL": ("str", "log_level"),
    "AYRAN_OFFLINE": ("bool", "offline"),
}

_LOG_LEVELS = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"}


def _defaults() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "state_root": "~/.local/state/ayran",
        "cache_root": "~/.cache/ayran",
        "config_root": "~/.config/ayran",
        "service_socket_name": "ayrand.sock",
        "journal_fsync": True,
        "sqlite_busy_timeout_ms": 5000,
        "snapshot_every_events": 10000,
        "security_override_allowed": False,
        "allow_install": False,
        "log_level": "INFO",
        "offline": False,
        "max_parallel_external_tools": 2,
        "max_parallel_models": 2,
        "max_rss_mib": 4096,
        "min_free_disk_mib": 4096,
        "default_wall_minutes": 240,
        "no_progress_minutes": 20,
        "graceful_stop_seconds": 20,
        "network_default": "deny",
        "allowed_network_classes": ["model_provider", "approved_rpc", "approved_source_fetch"],
        "require_pinned_rpc_block": True,
        "tools": {"slither": "0.11.5", "forge": "1.7.1", "solc_default": "0.8.28"},
    }


def _validate(key: str, value: Any, *, origin: str) -> None:
    if key not in _ALLOWED_TOP_LEVEL:
        raise ConfigError("CONFIG", f"unknown configuration key: {key!r}", details={"origin": origin})
    expected = _ALLOWED_TOP_LEVEL[key]
    if not isinstance(value, expected):
        raise ConfigError(
            "CONFIG",
            f"type mismatch for {key!r}: expected {expected}, got {type(value).__name__}",
            details={"origin": origin},
        )
    if key == "schema_version" and value != 1:
        raise ConfigError("CONFIG", "only schema_version=1 is supported")
    if key == "network_default" and value not in _ALLOWED_NETWORK_DEFAULTS:
        raise ConfigError("CONFIG", f"network_default must be one of {_ALLOWED_NETWORK_DEFAULTS}")
    if key == "log_level" and value not in _LOG_LEVELS:
        raise ConfigError("CONFIG", f"log_level must be one of {_LOG_LEVELS}")
    if key == "allowed_network_classes":
        if not isinstance(value, list):
            raise ConfigError("CONFIG", "allowed_network_classes must be a list")
        for item in value:
            if not isinstance(item, str):
                raise ConfigError("CONFIG", "allowed_network_classes must be a list of strings")
    if key == "tools":
        if not isinstance(value, dict):
            raise ConfigError("CONFIG", "tools must be a mapping")
        for tool_key, tool_value in value.items():
            if not isinstance(tool_key, str) or not isinstance(tool_value, str):
                raise ConfigError("CONFIG", "tools must map string names to string versions")


def _is_narrowed(key: str, existing: Any, requested: Any, *, security_override_allowed: bool) -> bool:
    if security_override_allowed:
        return True
    if key not in _MONOTONIC:
        return True
    direction, _floor = _MONOTONIC[key]
    if direction == "min":
        return int(requested) <= int(existing)
    if direction == "max":
        return int(requested) >= int(existing)
    if direction == "bool_true":
        return requested is True
    if direction == "bool_false":
        return requested is False
    return True


def _fold(
    base: dict[str, Any],
    updates: dict[str, Any],
    *,
    layer: str,
    origin: str,
    provenance: list[LoadSource],
    security_override_allowed: bool,
) -> dict[str, Any]:
    merged = dict(base)
    for key, value in updates.items():
        _validate(key, value, origin=origin)
        existing = merged.get(key)
        if not _is_narrowed(key, existing, value, security_override_allowed=security_override_allowed):
            raise ConfigError(
                "POLICY",
                f"layer {layer!r} attempted to weaken monotonic key {key!r} without an explicit security override",
                details={"key": key, "existing": existing, "requested": value, "origin": origin},
            )
        merged[key] = value
    provenance.append(LoadSource(layer=layer, origin=origin, values=dict(updates)))
    return merged


def _expand_home(value: Any) -> Any:
    if isinstance(value, str) and value.startswith("~/"):
        return str(Path.home() / value[2:])
    return value


def _load_toml_layer(layer: str, path: Path | None, origin_label: str) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    try:
        loaded = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(
            "CONFIG",
            f"invalid TOML in {origin_label}: {error}",
            details={"path": str(path)},
        ) from error
    if not isinstance(loaded, dict):
        raise ConfigError("CONFIG", f"{origin_label} must decode to a mapping", details={"path": str(path)})
    for key, value in loaded.items():
        if isinstance(value, dict):
            for inner_key, inner_value in value.items():
                if not isinstance(inner_value, (str, bool, int)):
                    raise ConfigError(
                        "CONFIG",
                        f"{origin_label} key {key}.{inner_key} is not a plain scalar",
                        details={"path": str(path)},
                    )
        elif not isinstance(value, (str, bool, int, list)):
            raise ConfigError(
                "CONFIG",
                f"{origin_label} key {key} has unsupported type {type(value).__name__}",
                details={"path": str(path)},
            )
    return loaded


def load_config(
    *,
    global_path: Path | None = None,
    project_path: Path | None = None,
    engagement_path: Path | None = None,
    env: dict[str, str] | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> EffectiveConfig:
    """Merge layers in order and return the effective config plus provenance."""

    if env is None:
        import os

        env = {key: value for key, value in os.environ.items() if key in _ALLOWED_ENV_KEYS}

    provenance: list[LoadSource] = []
    merged = _defaults()
    provenance.append(LoadSource(layer="defaults", origin="built-in", values=dict(_defaults())))

    # Determine ahead of time whether security_override is legitimately allowed:
    # only the private global file may set it, and only this loader permits that
    # one exception.
    security_override_allowed = False
    if global_path is not None and global_path.is_file():
        preloaded = _load_toml_layer("global", global_path, "private global file")
        if preloaded is not None and preloaded.get("security_override_allowed") is True:
            security_override_allowed = True

    layers: list[tuple[str, Path | None, str]] = [
        ("global", global_path, "private global file"),
        ("project", project_path, "project config file"),
        ("engagement", engagement_path, "engagement config file"),
    ]
    for layer, path, origin in layers:
        loaded = _load_toml_layer(layer, path, origin)
        if loaded is None:
            continue
        merged = _fold(
            merged,
            loaded,
            layer=layer,
            origin=f"{origin} {path}",
            provenance=provenance,
            security_override_allowed=security_override_allowed,
        )

    # Allowlisted env layer.
    env_updates: dict[str, Any] = {}
    for env_key, (kind, config_key) in _ALLOWED_ENV_KEYS.items():
        if env_key not in env or config_key is None:
            continue
        raw = env[env_key]
        if kind == "bool":
            env_updates[config_key] = raw.strip().lower() in {"1", "true", "yes", "on"}
        else:
            env_updates[config_key] = raw
    if env_updates:
        merged = _fold(
            merged,
            env_updates,
            layer="environment",
            origin="allowlisted environment",
            provenance=provenance,
            security_override_allowed=security_override_allowed,
        )

    # Explicit CLI overrides are the strongest layer.
    if cli_overrides:
        merged = _fold(
            merged,
            cli_overrides,
            layer="cli",
            origin="explicit CLI override",
            provenance=provenance,
            security_override_allowed=security_override_allowed,
        )

    tools = dict(_defaults()["tools"])
    tools.update(merged.get("tools", {}))
    merged["tools"] = tools

    config = EffectiveConfig(provenance=provenance)
    for field_name, field_value in merged.items():
        if field_name in {"tools", "provenance"}:
            continue
        expanded = _expand_home(field_value)
        if hasattr(config, field_name):
            setattr(config, field_name, expanded)
    config.tools = tools
    return config


def parse_cli_override(pairs: list[str]) -> dict[str, Any]:
    """Parse ``--set key=value`` CLI pairs into typed overrides."""

    overrides: dict[str, Any] = {}
    for pair in pairs:
        if "=" not in pair:
            raise ConfigError("CONFIG", f"--set expects key=value, got {pair!r}")
        key, raw = pair.split("=", 1)
        key = key.strip()
        if "," in raw:
            value: Any = [item.strip() for item in raw.split(",") if item.strip()]
        elif raw.strip().lower() in {"true", "false"}:
            value = raw.strip().lower() == "true"
        else:
            try:
                value = int(raw)
            except ValueError:
                value = raw
        overrides[key] = value
    return overrides
