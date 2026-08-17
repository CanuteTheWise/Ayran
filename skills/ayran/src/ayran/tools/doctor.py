"""Comprehensive tool diagnostics for ``ayran tools doctor``."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from ayran.config.models import EffectiveConfig
from ayran.tools.installer import plan_install
from ayran.tools.registry import CapabilityRegistry
from ayran.tools.types import Environment


async def tools_doctor(
    registry: CapabilityRegistry,
    *,
    config: EffectiveConfig | None = None,
) -> dict[str, Any]:
    path = registry.environment.path or os.environ.get("PATH", "")
    probes = {
        name: shutil.which(name, path=path) for name in ("solc", "forge", "cast", "anvil", "slither")
    }
    capabilities = []
    errors: list[str] = []
    for status in registry.list_capabilities():
        health = await registry.health(status.alias)
        plan = plan_install(registry, status.alias, config=config, env=registry.environment)
        item = {
            **status.as_dict(),
            "health": health.as_dict(),
            "install_plan": plan.as_dict(),
        }
        capabilities.append(item)
        if status.status != "available" and status.kind == "executable_adapter":
            errors.append(f"{status.alias}: {status.status} ({status.detail})")
        if status.kind == "http_adapter" and health.status not in {"available", "unverified"}:
            errors.append(f"{status.alias}: {health.status} ({health.detail})")
    return {
        "schema_version": "1.0.0",
        "doctor_status": "healthy" if not errors else "degraded",
        "path_probes": probes,
        "capabilities": capabilities,
        "errors": errors,
        "installers_enabled": bool(config.allow_install) if config is not None else False,
        "note": "unavailable optional tools degrade explicitly; adapters never install or mutate existing tools",
    }


def default_environment() -> Environment:
    roots: list[Path] = []
    extra_bins: list[str] = []
    home = Path.home()
    for item in (
        Path("/usr"),
        Path("/bin"),
        Path("/usr/local"),
        Path("/opt"),
        home / ".foundry",
        home / ".local",
        home / ".solc-select",
        home / ".svm",
    ):
        if item.exists():
            roots.append(item)
    for item in (
        home / ".foundry" / "bin",
        home / ".local" / "bin",
        Path("/usr/local/bin"),
        Path("/usr/bin"),
    ):
        if item.is_dir():
            extra_bins.append(str(item))
    python_root = Path(os.__file__).resolve().parents[1]
    roots.append(python_root)
    current = os.environ.get("PATH", "")
    path = os.pathsep.join([*extra_bins, current]) if extra_bins else current
    return Environment(
        path=path,
        home=home,
        allowed_binary_roots=tuple(roots),
    )
