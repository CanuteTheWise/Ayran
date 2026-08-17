"""Additive Learning Graph projection tables for outcomes, quarantine, and promotions."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

V5_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS learning_outcomes (
  outcome_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  run_id TEXT NOT NULL,
  outcome_type TEXT NOT NULL,
  hypothesis_id TEXT,
  object_json TEXT NOT NULL,
  PRIMARY KEY(outcome_id, revision)
);
CREATE TABLE IF NOT EXISTS learning_candidates (
  candidate_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  outcome_ref TEXT NOT NULL,
  promotion_stage TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(candidate_id, revision)
);
CREATE TABLE IF NOT EXISTS learning_reviews (
  review_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  candidate_id TEXT NOT NULL,
  reviewer_id TEXT NOT NULL,
  verdict TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(review_id, revision)
);
CREATE TABLE IF NOT EXISTS learning_promotions (
  release_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(release_id, revision)
);
CREATE TABLE IF NOT EXISTS quarantine_records (
  quarantine_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  subject_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(quarantine_id, revision)
);
CREATE TABLE IF NOT EXISTS routing_policies (
  policy_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  status TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(policy_id, revision)
);
CREATE INDEX IF NOT EXISTS ix_learning_outcomes_run
  ON learning_outcomes(run_id, outcome_type);
CREATE INDEX IF NOT EXISTS ix_learning_candidates_stage
  ON learning_candidates(promotion_stage, outcome_ref);
CREATE INDEX IF NOT EXISTS ix_quarantine_subject
  ON quarantine_records(subject_id, reason);
"""


@dataclass(frozen=True, slots=True)
class LearningMigration:
    version: int = 5
    name: str = "learning_projection_v5"

    def precheck(self, source_version: int) -> None:
        if source_version not in {4, 5}:
            raise ValueError("migration 5 accepts only a v4 or v5 projection")

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


MIGRATION = LearningMigration()
