"""Layer/Complete install, rollback, and uninstall against a receipt."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from ayran.graph.canonical import atomic_write, canonical_hash, canonical_line, utc_now
from ayran.release.errors import (
    INSTALL_REFUSED,
    PRIME_EXTERNAL_PROTECTED,
    RECEIPT_INVALID,
    ROLLBACK_DENIED,
    ReleaseError,
)
from ayran.release.paths import PINNED_TIME, RELEASE_VERSION
from ayran.release.signing import file_sha256

RECEIPT_VERSION = "1.0.0"


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ReleaseError(RECEIPT_INVALID, "receipt is not a JSON object")
    return payload


def plan_install(
    *,
    kind: str,
    prefix: Path,
    prime: Path | None = None,
    dry_run: bool = False,
    version: str = RELEASE_VERSION,
) -> dict[str, Any]:
    if kind not in {"layer", "complete"}:
        raise ReleaseError(INSTALL_REFUSED, f"unknown install kind {kind}")
    prefix = prefix.expanduser()
    versioned = prefix / "versions" / version
    pointer = prefix / "current"
    created = [
        str(versioned),
        str(versioned / "ayran"),
        str(prefix / "receipts"),
        str(pointer),
    ]
    if kind == "complete":
        created.append(str(versioned / "prime"))
    plan = {
        "schema_version": RECEIPT_VERSION,
        "kind": kind,
        "version": version,
        "prefix": str(prefix),
        "versioned": str(versioned),
        "pointer": str(pointer),
        "prime": str(prime) if prime else None,
        "created_paths": created,
        "dry_run": dry_run,
        "writes_windows_outside_dist": False,
        "mutates_external_prime": False,
        "mutates_external_tools": False,
        "network": False,
    }
    plan["plan_hash"] = canonical_hash(plan)
    return plan


def _write_tree(source: Path, destination: Path) -> list[str]:
    created: list[str] = []
    destination.mkdir(parents=True, exist_ok=True)
    created.append(str(destination))
    if source.is_file():
        target = destination / source.name
        shutil.copyfile(source, target)
        created.append(str(target))
        return created
    for path in sorted(source.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        created.append(str(target))
    return created


def install(
    *,
    kind: str,
    prefix: Path,
    source: Path,
    prime: Path | None = None,
    dry_run: bool = False,
    version: str = RELEASE_VERSION,
    created_at: str = PINNED_TIME,
) -> dict[str, Any]:
    plan = plan_install(kind=kind, prefix=prefix, prime=prime, dry_run=dry_run, version=version)
    if kind == "layer":
        if prime is None:
            raise ReleaseError(INSTALL_REFUSED, "Layer install requires --prime <path>")
        if not Path(prime).exists():
            raise ReleaseError(INSTALL_REFUSED, "Layer install refused: Prime path does not exist")
    if dry_run:
        return {**plan, "applied": False}
    versioned = Path(plan["versioned"])
    if versioned.exists():
        raise ReleaseError(INSTALL_REFUSED, f"refusing to overwrite existing version prefix {versioned}")
    created = _write_tree(source, versioned / "ayran")
    if kind == "complete":
        bundled = source / "vendor" / "cache" / "prime-agent-0.7.2.tgz"
        if not bundled.is_file() and (source / "ayran" / "vendor" / "cache" / "prime-agent-0.7.2.tgz").is_file():
            bundled = source / "ayran" / "vendor" / "cache" / "prime-agent-0.7.2.tgz"
        prime_prefix = versioned / "prime"
        prime_prefix.mkdir(parents=True, exist_ok=True)
        created.append(str(prime_prefix))
        if bundled.is_file():
            target = prime_prefix / bundled.name
            shutil.copyfile(bundled, target)
            created.append(str(target))
    pointer = Path(plan["pointer"])
    prior = ""
    if pointer.is_file() or pointer.is_symlink():
        prior = pointer.read_text(encoding="utf-8").strip() if pointer.is_file() else str(pointer)
    receipts = Path(plan["prefix"]) / "receipts"
    receipts.mkdir(parents=True, exist_ok=True)
    receipt_path = receipts / f"{kind}-{version}.json"
    receipt = {
        "schema_version": RECEIPT_VERSION,
        "kind": kind,
        "version": version,
        "prefix": plan["prefix"],
        "versioned": str(versioned),
        "pointer": str(pointer),
        "prior_pointer": prior,
        "created_paths": sorted(set([*created, str(versioned), str(receipts), str(pointer)])),
        "prime_classification": "observed-external" if kind == "layer" else "created-bundled-under-prefix",
        "external_prime": str(prime) if prime else "",
        "remove_external_prime": False,
        "remove_external_tools": False,
        "created_at": created_at or utc_now(),
        "source_hash": file_sha256(source) if source.is_file() else canonical_hash({"tree": str(source)}),
    }
    receipt["content_hash"] = canonical_hash({k: v for k, v in receipt.items() if k != "content_hash"})
    atomic_write(receipt_path, canonical_line(receipt))
    atomic_write(pointer, f"{versioned}\n".encode())
    receipt["receipt_path"] = str(receipt_path)
    receipt["applied"] = True
    return receipt


def rollback(receipt_path: Path) -> dict[str, Any]:
    receipt = _load_json(receipt_path)
    pointer = Path(str(receipt.get("pointer") or ""))
    prior = str(receipt.get("prior_pointer") or "")
    versioned = Path(str(receipt.get("versioned") or ""))
    if not pointer.parent.is_dir():
        raise ReleaseError(ROLLBACK_DENIED, "rollback pointer parent is missing")
    if prior:
        atomic_write(pointer, f"{prior}\n".encode())
    elif pointer.exists():
        pointer.unlink()
    removed: list[str] = []
    if versioned.is_dir():
        shutil.rmtree(versioned)
        removed.append(str(versioned))
    return {
        "ok": True,
        "restored_pointer": prior,
        "removed": removed,
        "external_prime_untouched": True,
        "external_tools_untouched": True,
    }


def uninstall(receipt_path: Path) -> dict[str, Any]:
    receipt = _load_json(receipt_path)
    if receipt.get("remove_external_prime") or receipt.get("remove_external_tools"):
        raise ReleaseError(PRIME_EXTERNAL_PROTECTED, "receipt tries to remove externally owned Prime or tools")
    prefix = Path(str(receipt.get("prefix") or ""))
    allowed = {Path(item).resolve() for item in receipt.get("created_paths") or []}
    removed: list[str] = []
    versioned = Path(str(receipt.get("versioned") or ""))
    if versioned.is_dir():
        resolved = versioned.resolve()
        owned = resolved in allowed
        if not owned:
            for item in allowed:
                try:
                    resolved.relative_to(item)
                    owned = True
                    break
                except ValueError:
                    try:
                        item.relative_to(resolved)
                        owned = True
                        break
                    except ValueError:
                        continue
        if owned:
            shutil.rmtree(versioned)
            removed.append(str(versioned))
    pointer = Path(str(receipt.get("pointer") or ""))
    if pointer.exists() and pointer.resolve() in allowed:
        pointer.unlink()
        removed.append(str(pointer))
    if receipt_path.is_file():
        receipt_path.unlink()
        removed.append(str(receipt_path))
    _ = prefix
    return {
        "ok": True,
        "removed": removed,
        "external_prime_untouched": True,
        "external_tools_untouched": True,
    }
