"""Locate the authored knowledge tree (registry, taxonomy, raw snapshots)."""

from __future__ import annotations

from pathlib import Path

PARSER_VERSION = "1.0.0"
TAXONOMY_VERSION = "1.0.0"
PINNED_TIME = "2026-08-14T00:00:00Z"
MAX_RECORD_BYTES = 65536


def default_knowledge_root() -> Path:
    """Return the repo ``knowledge/`` directory, matching M4 capability discovery."""

    repo = Path(__file__).resolve().parents[5]
    candidate = repo / "knowledge"
    if candidate.is_dir():
        return candidate
    return Path(__file__).resolve().parent / "data"


def registry_dir(root: Path) -> Path:
    return root / "registry"


def taxonomy_dir(root: Path) -> Path:
    return root / "taxonomy"


def raw_dir(root: Path, source_id: str | None = None) -> Path:
    base = root / "raw"
    return base / source_id if source_id else base


def staging_dir(root: Path, source_id: str | None = None) -> Path:
    base = root / "staging"
    return base / source_id if source_id else base


def quarantine_dir(root: Path) -> Path:
    return root / "quarantine"


def releases_dir(root: Path) -> Path:
    return root / "releases"


def current_pointer(root: Path) -> Path:
    return root / "current.json"
