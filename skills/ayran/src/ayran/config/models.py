"""Configuration models for M2 with layer provenance.

The effective configuration merges built-in defaults, the private global file,
the trusted project file, the engagement file, allowlisted environment
variables, and explicit CLI overrides.  Every recorded value carries the layer
it came from so run receipts are auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

LAYERS = (
    "defaults",
    "global",
    "project",
    "engagement",
    "environment",
    "cli",
)


@dataclass(frozen=True, slots=True)
class LoadSource:
    layer: str
    origin: str  # e.g. path or "env:AYRAN_STATE_ROOT"
    values: dict[str, Any]

    def provenance(self) -> dict[str, Any]:
        return {"layer": self.layer, "origin": self.origin, "value": self.values}


@dataclass(slots=True)
class EffectiveConfig:
    schema_version: int = 1
    state_root: str = "~/.local/state/ayran"
    cache_root: str = "~/.cache/ayran"
    config_root: str = "~/.config/ayran"
    service_socket_name: str = "ayrand.sock"
    journal_fsync: bool = True
    sqlite_busy_timeout_ms: int = 5000
    snapshot_every_events: int = 10000
    security_override_allowed: bool = False
    allow_install: bool = False
    log_level: str = "INFO"
    offline: bool = False
    # Resources (bounded by observed host floor)
    max_parallel_external_tools: int = 2
    max_parallel_models: int = 2
    max_rss_mib: int = 4600
    min_free_disk_mib: int = 4096
    default_wall_minutes: int = 240
    no_progress_minutes: int = 20
    graceful_stop_seconds: int = 20
    network_default: str = "deny"
    allowed_network_classes: list[str] = field(
        default_factory=lambda: ["model_provider", "approved_rpc", "approved_source_fetch"]
    )
    require_pinned_rpc_block: bool = True
    tools: dict[str, str] = field(
        default_factory=lambda: {"slither": "0.11.5", "forge": "1.7.1", "solc_default": "0.8.28"}
    )
    provenance: list[LoadSource] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "state_root": self.state_root,
            "cache_root": self.cache_root,
            "config_root": self.config_root,
            "service_socket_name": self.service_socket_name,
            "journal_fsync": self.journal_fsync,
            "sqlite_busy_timeout_ms": self.sqlite_busy_timeout_ms,
            "snapshot_every_events": self.snapshot_every_events,
            "security_override_allowed": self.security_override_allowed,
            "allow_install": self.allow_install,
            "log_level": self.log_level,
            "offline": self.offline,
            "max_parallel_external_tools": self.max_parallel_external_tools,
            "max_parallel_models": self.max_parallel_models,
            "max_rss_mib": self.max_rss_mib,
            "min_free_disk_mib": self.min_free_disk_mib,
            "default_wall_minutes": self.default_wall_minutes,
            "no_progress_minutes": self.no_progress_minutes,
            "graceful_stop_seconds": self.graceful_stop_seconds,
            "network_default": self.network_default,
            "allowed_network_classes": list(self.allowed_network_classes),
            "require_pinned_rpc_block": self.require_pinned_rpc_block,
            "tools": dict(self.tools),
            "provenance": [source.provenance() for source in self.provenance],
        }

