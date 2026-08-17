"""Locate Learning Graph quarantine, review, and promotion trees."""

from __future__ import annotations

from pathlib import Path

from ayran.knowledge.paths import default_knowledge_root

PARSER_VERSION = "1.0.0"
PINNED_TIME = "2026-08-15T00:00:00Z"
DEFAULT_TTL_DAYS = 30
BASELINE_ROUTING_POLICY = "ayran-routing-baseline-v1"


def default_learning_root() -> Path:
    """Learning releases live beside Global knowledge, never as Global current."""

    return default_knowledge_root() / "learning"


def quarantine_dir(root: Path) -> Path:
    return root / "quarantine"


def archive_dir(root: Path) -> Path:
    return root / "archive"


def staging_dir(root: Path) -> Path:
    return root / "staging"


def releases_dir(root: Path) -> Path:
    return root / "releases"


def current_pointer(root: Path) -> Path:
    return root / "current.json"


def routing_dir(root: Path) -> Path:
    return root / "routing"


def routing_current(root: Path) -> Path:
    return routing_dir(root) / "current.json"
