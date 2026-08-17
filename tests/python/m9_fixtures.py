"""Shared M9 helpers."""

from __future__ import annotations

from pathlib import Path

from ayran.graph.namespaces import TargetNamespace
from ayran.graph.recovery import GraphStore
from m5_fixtures import RUN_ID, TARGET_IDENTITY, TARGET_KEY

ROOT = Path(__file__).resolve().parents[2]


def open_store(tmp_path: Path) -> GraphStore:
    namespace = TargetNamespace(
        tmp_path / "graph",
        RUN_ID,
        TARGET_IDENTITY,
        TARGET_KEY,
        allow_unsafe_filesystem=True,
    )
    return GraphStore(namespace.root, namespace.stream, allow_unsafe_filesystem=True)
