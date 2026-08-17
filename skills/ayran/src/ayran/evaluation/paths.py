"""Locate sealed evaluation inputs and immutable result trees."""

from __future__ import annotations

from pathlib import Path

PINNED_TIME = "2026-08-15T00:00:00Z"
PARSER_VERSION = "1.0.0"
RELEASE_VERSION = "0.1.5"
FIXED_SEEDS = (7, 13, 21)
RUBRIC_VERSION = "ayran-eval-rubric-v1"


def repository_root() -> Path:
    return Path(__file__).resolve().parents[5]


def evals_root(override: Path | str | None = None) -> Path:
    if override is not None:
        return Path(override)
    return repository_root() / "evals"


def sealed_catalog_path(root: Path | None = None) -> Path:
    return evals_root(root) / "sealed" / "catalog.json"


def rubric_path(root: Path | None = None) -> Path:
    return evals_root(root) / "judges" / "rubric-v1.json"


def results_root(override: Path | str | None = None) -> Path:
    if override is not None:
        return Path(override)
    return evals_root() / "results"


def session_dir(session_id: str, *, results: Path | str | None = None) -> Path:
    return results_root(results) / session_id


def session_manifest_path(session_id: str, *, results: Path | str | None = None) -> Path:
    return session_dir(session_id, results=results) / "manifest.json"
