"""Quarantine workflow: captured outcomes never influence production routing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from ayran.context.ids import content_id
from ayran.graph.canonical import canonical_hash
from ayran.graph.recovery import GraphStore
from ayran.learning.errors import LEARNING_NOT_FOUND, TTL_EXPIRED, LearningError
from ayran.learning.load import load_candidate, load_outcome, load_reviews
from ayran.learning.models import LearningOutcome, QuarantineRecord
from ayran.learning.paths import DEFAULT_TTL_DAYS, PINNED_TIME
from ayran.learning.persist import persist_outcome, persist_quarantine


def _parse_time(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _deadline(created_at: str, ttl_days: int) -> str:
    return (_parse_time(created_at) + timedelta(days=ttl_days)).isoformat().replace("+00:00", "Z")


def _queue_score(novelty: float, severity: float, cost: float) -> float:
    return round(float(novelty) * float(severity) * float(cost), 6)


def submit_for_review(
    outcome_id: str,
    *,
    store: GraphStore | None = None,
    outcome: LearningOutcome | None = None,
    created_at: str = PINNED_TIME,
    ttl_days: int = DEFAULT_TTL_DAYS,
    now: str | None = None,
) -> QuarantineRecord:
    """Move a captured outcome into the review queue. Not production knowledge."""

    loaded = outcome
    if loaded is None and store is not None:
        loaded = load_outcome(store, outcome_id)
    if loaded is None:
        raise LearningError(LEARNING_NOT_FOUND, f"outcome {outcome_id} is not in the Learning Graph")
    current = now or created_at
    if _parse_time(current) > _parse_time(_deadline(loaded.created_at, ttl_days)):
        record = QuarantineRecord(
            quarantine_id=content_id("qrn", outcome_id, "expired"),
            subject_id=outcome_id,
            subject_kind="outcome",
            reason="ttl_expired",
            created_at=current,
            review_deadline=_deadline(loaded.created_at, ttl_days),
            status="archived",
            novelty_score=loaded.novelty_score,
            severity_score=loaded.severity_score,
            cost_to_validate=loaded.cost_to_validate,
            queue_score=_queue_score(loaded.novelty_score, loaded.severity_score, loaded.cost_to_validate),
            inspectable=True,
            production_retrievable=False,
        )
        if store is not None:
            loaded.promotion_stage = "archived"
            persist_outcome(store, loaded, created_at=current)
            persist_quarantine(store, record, created_at=current)
        return record
    loaded.promotion_stage = "quarantined"
    record = QuarantineRecord(
        quarantine_id=content_id("qrn", outcome_id, loaded.content_hash),
        subject_id=outcome_id,
        subject_kind="outcome",
        reason="captured_awaiting_review",
        created_at=created_at,
        review_deadline=_deadline(loaded.created_at, ttl_days),
        status="queued",
        novelty_score=loaded.novelty_score,
        severity_score=loaded.severity_score,
        cost_to_validate=loaded.cost_to_validate,
        queue_score=_queue_score(loaded.novelty_score, loaded.severity_score, loaded.cost_to_validate),
        inspectable=True,
        production_retrievable=False,
    )
    if store is not None:
        persist_outcome(store, loaded, created_at=created_at)
        persist_quarantine(store, record, created_at=created_at)
    return record


def archive_expired(
    store: GraphStore,
    *,
    now: str,
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> list[str]:
    archived: list[str] = []
    for record in list_queue(store, include_archived=True):
        if record.status == "archived":
            continue
        if _parse_time(now) <= _parse_time(record.review_deadline):
            continue
        record.status = "archived"
        record.reason = "ttl_expired"
        record.production_retrievable = False
        persist_quarantine(store, record, created_at=now)
        outcome = load_outcome(store, record.subject_id)
        if outcome is not None:
            outcome.promotion_stage = "archived"
            persist_outcome(store, outcome, created_at=now)
        archived.append(record.subject_id)
    return archived


def list_queue(
    store: GraphStore,
    *,
    include_archived: bool = False,
    include_failed: bool = True,
) -> list[QuarantineRecord]:
    from ayran.learning.load import load_quarantines

    records = load_quarantines(store)
    visible: list[QuarantineRecord] = []
    for record in records:
        if record.status == "archived" and not include_archived:
            continue
        if record.status == "rejected" and not include_failed:
            continue
        visible.append(record)
    return sorted(visible, key=lambda item: (-item.queue_score, item.subject_id))


def record_is_production_retrievable(store: GraphStore, subject_id: str) -> bool:
    candidate = load_candidate(store, subject_id)
    if candidate is not None:
        return candidate.promotion_stage == "released"
    outcome = load_outcome(store, subject_id)
    if outcome is None:
        return False
    return outcome.promotion_stage == "released"


def require_not_expired(record: QuarantineRecord, *, now: str) -> None:
    if record.status == "archived" or _parse_time(now) > _parse_time(record.review_deadline):
        raise LearningError(TTL_EXPIRED, "quarantined outcome expired and was archived, not promoted")


def queue_payload(store: GraphStore) -> dict[str, Any]:
    items = []
    for record in list_queue(store, include_archived=True, include_failed=True):
        items.append(
            {
                **record.model_dump(mode="json"),
                "content_hash": canonical_hash(record.model_dump(mode="json")),
                "reviews": [
                    item.model_dump(mode="json")
                    for item in load_reviews(store, record.subject_id)
                ],
            }
        )
    return {
        "schema_version": "1.0.0",
        "count": len(items),
        "queue": items,
    }
