"""Additive Global knowledge projection tables for corpus records and conflicts."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

V4_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS knowledge_records (
  record_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  record_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  safe_for_retrieval INTEGER NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(record_id, revision)
);
CREATE TABLE IF NOT EXISTS conflict_groups (
  group_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  kind TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(group_id, revision)
);
CREATE TABLE IF NOT EXISTS corpus_releases (
  release_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  content_hash TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(release_id, revision)
);
CREATE INDEX IF NOT EXISTS ix_knowledge_records_type
  ON knowledge_records(record_type, source_id);
CREATE INDEX IF NOT EXISTS ix_knowledge_records_retrieval
  ON knowledge_records(safe_for_retrieval, record_type);
"""


@dataclass(frozen=True, slots=True)
class KnowledgeMigration:
    version: int = 4
    name: str = "knowledge_projection_v4"

    def precheck(self, source_version: int) -> None:
        if source_version not in {3, 4}:
            raise ValueError("migration 4 accepts only a v3 or v4 projection")

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


MIGRATION = KnowledgeMigration()
