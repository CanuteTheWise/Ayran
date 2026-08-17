"""Load latest Learning Graph records from the SQLite projection."""

from __future__ import annotations

import json
from typing import Any

from ayran.graph.recovery import GraphStore
from ayran.learning.models import (
    LearningCandidate,
    LearningOutcome,
    LearningReview,
    PromotionRelease,
    QuarantineRecord,
    RoutingPolicy,
)


def _decode(payload: Any) -> dict[str, Any] | None:
    if isinstance(payload, dict):
        if "properties" in payload:
            for item in payload.get("properties") or []:
                if isinstance(item, dict) and item.get("name") == "record_json":
                    raw = item.get("value")
                    if isinstance(raw, str) and raw.startswith("{"):
                        loaded = json.loads(raw)
                        return loaded if isinstance(loaded, dict) else None
        return payload
    if isinstance(payload, str) and payload.startswith("{"):
        loaded = json.loads(payload)
        return loaded if isinstance(loaded, dict) else None
    return None


def _latest(store: GraphStore, table: str, id_column: str, object_id: str) -> dict[str, Any] | None:
    sql = (
        f"SELECT object_json FROM {table} WHERE {id_column}=? "
        "ORDER BY revision DESC LIMIT 1"
    )
    with store.projection.snapshot() as connection:
        try:
            row = connection.execute(sql, (object_id,)).fetchone()
        except Exception:
            return None
    if row is None:
        return None
    return _decode(row["object_json"] if not isinstance(row, dict) else row.get("object_json"))


def _all_latest(store: GraphStore, table: str, id_column: str) -> list[dict[str, Any]]:
    sql = (
        f"SELECT t.object_json FROM {table} t JOIN ("
        f"SELECT {id_column} AS id, MAX(revision) AS revision FROM {table} GROUP BY {id_column}"
        f") latest ON t.{id_column}=latest.id AND t.revision=latest.revision"
    )
    records: list[dict[str, Any]] = []
    with store.projection.snapshot() as connection:
        try:
            rows = connection.execute(sql).fetchall()
        except Exception:
            return []
        for row in rows:
            payload = _decode(row["object_json"])
            if payload:
                records.append(payload)
    return records


def load_outcome(store: GraphStore, outcome_id: str) -> LearningOutcome | None:
    payload = _latest(store, "learning_outcomes", "outcome_id", outcome_id)
    return LearningOutcome.model_validate(payload) if payload else None


def load_outcomes(store: GraphStore) -> list[LearningOutcome]:
    return [LearningOutcome.model_validate(item) for item in _all_latest(store, "learning_outcomes", "outcome_id")]


def load_candidate(store: GraphStore, candidate_id: str) -> LearningCandidate | None:
    payload = _latest(store, "learning_candidates", "candidate_id", candidate_id)
    return LearningCandidate.model_validate(payload) if payload else None


def load_candidates(store: GraphStore, *, released_only: bool = False) -> list[LearningCandidate]:
    items = [
        LearningCandidate.model_validate(item)
        for item in _all_latest(store, "learning_candidates", "candidate_id")
    ]
    if released_only:
        return [item for item in items if item.promotion_stage == "released"]
    return items


def load_review(store: GraphStore, review_id: str) -> LearningReview | None:
    payload = _latest(store, "learning_reviews", "review_id", review_id)
    return LearningReview.model_validate(payload) if payload else None


def load_reviews(store: GraphStore, candidate_id: str | None = None) -> list[LearningReview]:
    items = [
        LearningReview.model_validate(item)
        for item in _all_latest(store, "learning_reviews", "review_id")
    ]
    if candidate_id:
        return [item for item in items if item.candidate_id == candidate_id]
    return items


def load_quarantine(store: GraphStore, quarantine_id: str) -> QuarantineRecord | None:
    payload = _latest(store, "quarantine_records", "quarantine_id", quarantine_id)
    return QuarantineRecord.model_validate(payload) if payload else None


def load_quarantines(store: GraphStore) -> list[QuarantineRecord]:
    return [
        QuarantineRecord.model_validate(item)
        for item in _all_latest(store, "quarantine_records", "quarantine_id")
    ]


def load_promotions(store: GraphStore) -> list[PromotionRelease]:
    return [
        PromotionRelease.model_validate(item)
        for item in _all_latest(store, "learning_promotions", "release_id")
    ]


def load_promotion(store: GraphStore, release_id: str) -> PromotionRelease | None:
    payload = _latest(store, "learning_promotions", "release_id", release_id)
    return PromotionRelease.model_validate(payload) if payload else None


def load_routing_policies(store: GraphStore) -> list[RoutingPolicy]:
    return [
        RoutingPolicy.model_validate(item)
        for item in _all_latest(store, "routing_policies", "policy_id")
    ]
