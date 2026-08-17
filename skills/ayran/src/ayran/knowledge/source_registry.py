"""Approved Global Graph source registry. Versioned YAML; no silent deletion."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ayran.graph.canonical import utc_now
from ayran.knowledge.errors import SOURCE_NOT_FOUND, KnowledgeError
from ayran.knowledge.models import SourceRegistryEntry, TombstoneRecord
from ayran.knowledge.paths import PINNED_TIME, registry_dir
from ayran.tools.yaml_lite import YamlLiteError, dump_yaml, load_yaml

SourceId = str


def _entry_path(root: Path, source_id: str) -> Path:
    return registry_dir(root) / f"{source_id}.yaml"


def _load_mapping(path: Path) -> dict[str, Any]:
    try:
        loaded = load_yaml(path.read_text(encoding="utf-8"))
    except YamlLiteError as error:
        raise KnowledgeError("CONTRACT_INVALID", f"registry YAML is invalid: {error}") from error
    if not isinstance(loaded, dict):
        raise KnowledgeError("CONTRACT_INVALID", f"registry file {path.name} must be a mapping")
    return loaded


def register_source(root: Path, entry: SourceRegistryEntry) -> SourceId:
    registry_dir(root).mkdir(parents=True, exist_ok=True)
    path = _entry_path(root, entry.source_id)
    payload = entry.model_dump(mode="json")
    path.write_text(dump_yaml(payload), encoding="utf-8")
    return entry.source_id


def get_source(root: Path, source_id: str) -> SourceRegistryEntry:
    path = _entry_path(root, source_id)
    if not path.is_file():
        raise KnowledgeError(SOURCE_NOT_FOUND, f"source {source_id!r} is not registered")
    return SourceRegistryEntry.model_validate(_load_mapping(path))


def list_sources(root: Path, phase: str | None = None) -> list[SourceRegistryEntry]:
    directory = registry_dir(root)
    if not directory.is_dir():
        return []
    entries: list[SourceRegistryEntry] = []
    for path in sorted(directory.glob("*.yaml")):
        if path.name.endswith(".tombstone.yaml"):
            continue
        entry = SourceRegistryEntry.model_validate(_load_mapping(path))
        if phase and entry.phase != phase:
            continue
        entries.append(entry)
    return sorted(entries, key=lambda item: item.source_id)


def save_source(root: Path, entry: SourceRegistryEntry) -> None:
    register_source(root, entry)


def tombstone_source(root: Path, source_id: str, reason: str, *, when: str | None = None) -> TombstoneRecord:
    entry = get_source(root, source_id)
    previous = entry.phase
    stamp = when or PINNED_TIME or utc_now()
    updated = entry.model_copy(update={"phase": "tombstoned", "notes": reason})
    save_source(root, updated)
    record = TombstoneRecord(
        source_id=source_id,
        reason=reason,
        tombstoned_at=stamp,
        previous_phase=previous,
    )
    tomb_path = registry_dir(root) / f"{source_id}.tombstone.yaml"
    tomb_path.write_text(dump_yaml(record.model_dump(mode="json")), encoding="utf-8")
    return record
