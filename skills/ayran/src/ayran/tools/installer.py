"""Controlled installer design.  Execution is disabled unless explicitly enabled."""

from __future__ import annotations

import shutil
from pathlib import Path

from ayran.config.models import EffectiveConfig
from ayran.tools.base import default_install_plan
from ayran.tools.errors import INSTALL_DISABLED, ToolError
from ayran.tools.receipts import InstallReceipt, write_receipt
from ayran.tools.registry import CapabilityRegistry
from ayran.tools.types import Environment, InstallPlan


def _drvfs_warning(prefix: Path) -> str | None:
    posix = prefix.as_posix().lower()
    if posix.startswith("/mnt/") or (len(posix) >= 2 and posix[1] == ":"):
        return "refusing to install onto DrvFS or a Windows drive; use a WSL ext4 prefix"
    return None


def _free_mib(prefix: Path) -> int | None:
    try:
        usage = shutil.disk_usage(prefix if prefix.exists() else prefix.parent)
    except OSError:
        return None
    return int(usage.free / (1024 * 1024))


def plan_install(
    registry: CapabilityRegistry,
    capability_id: str,
    *,
    config: EffectiveConfig | None = None,
    env: Environment | None = None,
    prefix: Path | None = None,
) -> InstallPlan:
    adapter = registry.get_adapter(capability_id, require_available=False)
    environment = env or registry.environment
    plan = default_install_plan(
        adapter.manifest,
        getattr(adapter, "alias", capability_id),
        enabled=False,
        reason="controlled installation is disabled by default (allow_install=false)",
    )
    target = prefix or Path(plan.install_prefix).expanduser()
    plan.drvfs_warning = _drvfs_warning(target)
    plan.free_ext4_mib = _free_mib(target)
    if config is not None and config.allow_install:
        plan.enabled = False
        plan.blocked_reason = (
            "allow_install is true but installer execution still requires an explicit "
            "human-approved InstallPlan hash; adapters never mutate existing tools"
        )
    if plan.drvfs_warning:
        plan.blocked_reason = plan.drvfs_warning
    _ = environment
    return plan


def execute_install(
    registry: CapabilityRegistry,
    capability_id: str,
    *,
    config: EffectiveConfig,
    approved: bool,
    receipt_dir: Path,
) -> InstallReceipt:
    _ = registry
    _ = capability_id
    _ = receipt_dir
    if not config.allow_install or not approved:
        raise ToolError(
            INSTALL_DISABLED,
            "installer execution is disabled; detection and invocation never install, upgrade, or copy tools",
        )
    raise ToolError(
        INSTALL_DISABLED,
        "installer execution is designed but not enabled in M4; no tool binaries are mutated",
    )


def write_plan_receipt(plan: InstallPlan, receipt_dir: Path) -> Path:
    receipt = InstallReceipt.from_plan(plan)
    return write_receipt(receipt_dir, receipt)
