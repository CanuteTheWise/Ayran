"""Additive evidence projection tables for gate verdicts, findings, PoC, and dedup."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

V3_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS gate_verdicts (
  verdict_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  gate TEXT NOT NULL,
  decision TEXT NOT NULL,
  hypothesis_id TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(verdict_id, revision)
);
CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  status TEXT NOT NULL,
  hypothesis_id TEXT,
  object_json TEXT NOT NULL,
  PRIMARY KEY(finding_id, revision)
);
CREATE TABLE IF NOT EXISTS poc_runs (
  poc_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  hypothesis_id TEXT NOT NULL,
  status TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(poc_id, revision)
);
CREATE TABLE IF NOT EXISTS dedup_clusters (
  cluster_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  status TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(cluster_id, revision)
);
CREATE INDEX IF NOT EXISTS ix_gate_verdicts_hypothesis
  ON gate_verdicts(hypothesis_id, gate);
CREATE INDEX IF NOT EXISTS ix_findings_status
  ON findings(status);
CREATE INDEX IF NOT EXISTS ix_poc_hypothesis
  ON poc_runs(hypothesis_id, status);
"""


@dataclass(frozen=True, slots=True)
class EvidenceMigration:
    version: int = 3
    name: str = "evidence_projection_v3"

    def precheck(self, source_version: int) -> None:
        if source_version not in {2, 3}:
            raise ValueError("migration 3 accepts only a v2 or v3 projection")

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


MIGRATION = EvidenceMigration()
