"""Software Bill of Materials for Ayran Layer and Ayran Complete."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ayran.graph.canonical import canonical_hash
from ayran.release.paths import PRIME_ARCHIVE_SHA256, PRIME_COMMIT, PRIME_VERSION, repository_root
from ayran.release.url_closure import build_complete_deps


def _uv_packages(lock_text: str) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    name = ""
    version = ""
    for line in lock_text.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            if name:
                packages.append({"name": name, "version": version, "ecosystem": "pypi"})
            name = ""
            version = ""
            continue
        if stripped.startswith("name = ") and not name:
            name = stripped.split("=", 1)[1].strip().strip('"')
        elif stripped.startswith("version = ") and name and not version:
            version = stripped.split("=", 1)[1].strip().strip('"')
    if name:
        packages.append({"name": name, "version": version, "ecosystem": "pypi"})
    return packages


def _capability_tools(root: Path) -> list[dict[str, str]]:
    tools: list[dict[str, str]] = []
    support = root / "compatibility" / "tool-support.json"
    if support.is_file():
        payload = json.loads(support.read_text(encoding="utf-8"))
        for item in payload.get("tools") or []:
            if isinstance(item, dict):
                tools.append(
                    {
                        "id": str(item.get("id") or ""),
                        "version": str(item.get("expected_version") or ""),
                        "ownership": "external",
                    }
                )
    return tools


def build_sbom(*, kind: str, root: Path | str | None = None) -> dict[str, Any]:
    repo = Path(root) if root is not None else repository_root()
    uv_lock = repo / "uv.lock"
    python = _uv_packages(uv_lock.read_text(encoding="utf-8")) if uv_lock.is_file() else []
    closure = build_complete_deps(repo)
    npm = [
        {"name": item["name"], "version": item.get("version") or "", "sha256": item["sha256"]}
        for item in closure["ayran_packages"]
        if item.get("name")
    ]
    knowledge = []
    pointer = repo / "knowledge" / "current.json"
    if pointer.is_file():
        knowledge.append({"release": "current", "hash": canonical_hash(json.loads(pointer.read_text(encoding="utf-8")))})
    else:
        knowledge.append({"release": "registry-only", "hash": canonical_hash({"registry": True})})
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "kind": kind,
        "python": python,
        "npm": npm,
        "tools": _capability_tools(repo),
        "knowledge": knowledge,
        "prime": None,
    }
    if kind == "ayran-complete":
        payload["prime"] = {
            "version": PRIME_VERSION,
            "commit": PRIME_COMMIT,
            "archive_sha256": PRIME_ARCHIVE_SHA256,
        }
        payload["prime_url_pins"] = closure["prime_packages"]
    payload["content_hash"] = canonical_hash({k: v for k, v in payload.items() if k != "content_hash"})
    return payload
