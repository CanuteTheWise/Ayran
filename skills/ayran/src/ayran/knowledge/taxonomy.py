"""Taxonomy loaders and category assignment for normalized records."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ayran.knowledge.models import KnowledgeRecord
from ayran.knowledge.paths import taxonomy_dir
from ayran.tools.yaml_lite import load_yaml

TAXONOMY_FILES = ("mechanisms.yaml", "attack_surfaces.yaml", "protocols.yaml", "tools.yaml")


def load_taxonomy(root: Path) -> dict[str, Any]:
    directory = taxonomy_dir(root)
    loaded: dict[str, Any] = {}
    for name in TAXONOMY_FILES:
        path = directory / name
        if not path.is_file():
            loaded[name.removesuffix(".yaml")] = {"entries": []}
            continue
        document = load_yaml(path.read_text(encoding="utf-8"))
        loaded[name.removesuffix(".yaml")] = document if isinstance(document, dict) else {"entries": []}
    return loaded


def _entries(taxonomy: dict[str, Any], family: str) -> list[dict[str, Any]]:
    document = taxonomy.get(family) or {}
    items = document.get("entries") if isinstance(document, dict) else None
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def assign_taxonomy(record: KnowledgeRecord, taxonomy: dict[str, Any]) -> list[str]:
    assigned: list[str] = []
    blob = " ".join(
        [
            record.record_type,
            record.title,
            record.summary,
            record.mechanism or "",
            record.protocol or "",
            record.component or "",
            record.language or "",
            " ".join(record.applicability_predicates),
            " ".join(record.code_signals),
        ]
    ).lower()
    for family in ("mechanisms", "attack_surfaces", "protocols"):
        for entry in _entries(taxonomy, family):
            identifier = str(entry.get("id") or "")
            if not identifier:
                continue
            aliases = [str(item).lower() for item in (entry.get("aliases") or [])]
            aliases.append(identifier.lower())
            aliases.append(str(entry.get("title") or "").lower())
            if any(alias and alias in blob for alias in aliases):
                assigned.append(f"{family}:{identifier}")
    return sorted(set(assigned))


def tool_capabilities_for(
    taxonomy: dict[str, Any],
    *,
    attack_surface: str | None = None,
    protocol: str | None = None,
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    needle_surface = (attack_surface or "").lower()
    needle_protocol = (protocol or "").lower()
    for entry in _entries(taxonomy, "tools"):
        surfaces = [str(item).lower() for item in (entry.get("attack_surfaces") or [])]
        protocols = [str(item).lower() for item in (entry.get("protocols") or [])]
        mechanisms = [str(item).lower() for item in (entry.get("mechanisms") or [])]
        if needle_surface and needle_surface not in surfaces and needle_surface not in mechanisms:
            continue
        if needle_protocol and needle_protocol not in protocols:
            continue
        matches.append(entry)
    return matches
