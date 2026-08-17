"""Additive cognitive projection tables for coverage grids, maps, and router runtime."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

V2_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS coverage_grid (
  cell_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  cluster_id TEXT NOT NULL,
  dimension TEXT NOT NULL,
  cell_state TEXT NOT NULL,
  risk_score INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(cell_id, revision)
);
CREATE TABLE IF NOT EXISTS cognitive_maps (
  map_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  map_type TEXT NOT NULL,
  cluster_id TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(map_id, revision)
);
CREATE TABLE IF NOT EXISTS router_runtime (
  object_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  kind TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(object_id, revision)
);
CREATE INDEX IF NOT EXISTS ix_coverage_grid_cluster
  ON coverage_grid(cluster_id, cell_state, risk_score);
CREATE INDEX IF NOT EXISTS ix_maps_cluster
  ON cognitive_maps(cluster_id, map_type);
"""


@dataclass(frozen=True, slots=True)
class CognitiveMigration:
    version: int = 2
    name: str = "cognitive_projection_v2"

    def precheck(self, source_version: int) -> None:
        if source_version not in {1, 2}:
            raise ValueError("migration 2 accepts only a v1 or v2 projection")

    def apply_event_transform(self, event: Mapping[str, Any]) -> Mapping[str, Any]:
        return event

    def rebuild_projection(
        self,
        destination: Path,
        batches: Iterable[tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]],
        rebuild: Callable[
            [Path, Iterable[tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]]], None
        ],
    ) -> None:
        rebuild(destination, batches)

    def validate(self, integrity_result: tuple[bool, list[str]]) -> None:
        ok, issues = integrity_result
        if not ok:
            raise ValueError("migration validation failed: " + "; ".join(issues))


MIGRATION = CognitiveMigration()
