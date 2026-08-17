"""Machine-readable install receipts and rollback of receipt-listed paths only."""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ayran.graph.canonical import utc_now
from ayran.graph.ids import new_id
from ayran.tools.errors import INSTALL_DISABLED, ToolError
from ayran.tools.types import InstallPlan


@dataclass(slots=True)
class InstallReceipt:
    schema_version: str
    receipt_id: str
    created_at: str
    capability_id: str
    alias: str
    tool: str
    version: str
    source: str
    prefix: str
    created_paths: list[str]
    prior_pointer: str | None
    verification: dict[str, Any]
    enabled: bool

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_plan(plan: InstallPlan) -> InstallReceipt:
        return InstallReceipt(
            schema_version="1.0.0",
            receipt_id=new_id("rcp"),
            created_at=utc_now(),
            capability_id=plan.capability_id,
            alias=plan.alias,
            tool=plan.tool,
            version=plan.version,
            source=plan.source,
            prefix=plan.install_prefix,
            created_paths=[],
            prior_pointer=None,
            verification={"status": "not-executed", "reason": plan.blocked_reason},
            enabled=plan.enabled,
        )


def write_receipt(directory: Path, receipt: InstallReceipt) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{receipt.receipt_id}.json"
    path.write_text(json.dumps(receipt.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_receipt(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ToolError("CONTRACT_INVALID", "install receipt must be a JSON object")
    return payload


def rollback(receipt_path: Path, *, prefix: Path) -> dict[str, Any]:
    """Restore the prior pointer and remove only receipt-listed paths under prefix."""

    receipt = read_receipt(receipt_path)
    created = receipt.get("created_paths")
    if not isinstance(created, list):
        raise ToolError("CONTRACT_INVALID", "receipt created_paths must be a list")
    prefix_real = prefix.resolve(strict=False)
    removed: list[str] = []
    for item in created:
        target = Path(str(item)).resolve(strict=False)
        try:
            target.relative_to(prefix_real)
        except ValueError as error:
            raise ToolError(
                INSTALL_DISABLED,
                "refusing to remove a path that is not inside the receipt prefix",
                details={"path": str(target)},
            ) from error
        if target.is_dir():
            shutil.rmtree(target)
        elif target.is_file():
            target.unlink()
        removed.append(str(target))
    return {
        "schema_version": "1.0.0",
        "rolled_back": True,
        "prior_pointer": receipt.get("prior_pointer"),
        "removed_paths": removed,
    }
