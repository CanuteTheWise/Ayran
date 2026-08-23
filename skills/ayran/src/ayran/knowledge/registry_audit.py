"""Fabricated-entry and provenance-completeness audit of the source registry.

Spec 12-R4 F: every ``knowledge/registry/*.yaml`` must parse as a
``SourceRegistryEntry``; phases ``ingested``/``active`` require a non-empty
``pin.commit``, ``pin.archive_sha256``, and an origin URI; the known-
fabricated names must never appear; olaradial is valid only as the permanent
blacklist lineage record (blacklisted flags + catalogued phase).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ayran.knowledge.models import SourceRegistryEntry
from ayran.knowledge.paths import registry_dir
from ayran.tools.yaml_lite import YamlLiteError, load_yaml

FABRICATED_SOURCE_IDS = frozenset({"foundryvtt", "htsx"})
REQUIRED_PIN_PHASES = frozenset({"ingested", "active"})
VALID_URI_SCHEMES = frozenset({"http", "https"})


def _violation(source_id: str, rule: str, detail: str) -> dict[str, str]:
    return {"source_id": source_id, "rule": rule, "detail": detail}


def audit_registry(knowledge_root: Path | str | None = None) -> dict[str, Any]:
    """Audit every registry entry; returns ``{ok, violations, checked}``."""

    root = Path(knowledge_root) if knowledge_root is not None else Path("knowledge")
    directory = registry_dir(root)
    paths = sorted(path for path in directory.glob("*.yaml") if not path.name.endswith(".tombstone.yaml"))
    violations: list[dict[str, str]] = []
    for path in paths:
        source_id = path.stem
        try:
            mapping = load_yaml(path.read_text(encoding="utf-8"))
            if not isinstance(mapping, dict):
                raise YamlLiteError("registry file must be a mapping")
            entry = SourceRegistryEntry.model_validate({str(key): value for key, value in mapping.items()})
        except (YamlLiteError, ValueError) as error:
            violations.append(_violation(source_id, "parse", f"{type(error).__name__}: {error}"))
            continue
        if entry.source_id in FABRICATED_SOURCE_IDS:
            violations.append(
                _violation(entry.source_id, "fabricated", "known-fabricated source id must never be registered")
            )
        if entry.phase in REQUIRED_PIN_PHASES:
            if not entry.pin.commit.strip():
                violations.append(_violation(entry.source_id, "pin.commit", f"phase {entry.phase} requires a pinned commit"))
            if not entry.pin.archive_sha256.strip():
                violations.append(
                    _violation(entry.source_id, "pin.archive_sha256", f"phase {entry.phase} requires an archive hash")
                )
            origin = urlparse(entry.origin)
            if origin.scheme not in VALID_URI_SCHEMES or not origin.netloc:
                violations.append(
                    _violation(entry.source_id, "origin", f"phase {entry.phase} requires an origin URI")
                )
        if entry.source_id == "olaradial":
            blacklisted = any(flag.startswith("blacklisted") for flag in entry.contamination_flags)
            if entry.phase != "catalogued" or not blacklisted:
                violations.append(
                    _violation(
                        "olaradial",
                        "olaradial-lineage",
                        "valid only as the permanent blacklist record: blacklisted flags + catalogued phase",
                    )
                )
    violations.sort(key=lambda item: (item["source_id"], item["rule"]))
    return {
        "schema_version": "1.0.0",
        "ok": not violations,
        "violations": violations,
        "checked": len(paths),
    }
