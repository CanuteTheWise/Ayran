"""Record independent reviews of quarantined outcomes and candidates."""

from __future__ import annotations

from ayran.context.ids import content_id
from ayran.graph.canonical import canonical_hash
from ayran.graph.recovery import GraphStore
from ayran.learning.errors import LEARNING_NOT_FOUND, LearningError
from ayran.learning.load import load_candidate, load_outcome
from ayran.learning.models import LearningReview, PromotionStage, ReviewerType, ReviewVerdict
from ayran.learning.paths import PINNED_TIME
from ayran.learning.persist import persist_candidate, persist_outcome, persist_review
from ayran.learning.quarantine import list_queue


def record_review(
    subject_id: str,
    *,
    reviewer_id: str,
    reviewer_type: ReviewerType,
    verdict: ReviewVerdict,
    notes: str = "",
    store: GraphStore,
    created_at: str = PINNED_TIME,
) -> LearningReview:
    candidate = load_candidate(store, subject_id)
    outcome = load_outcome(store, subject_id)
    if candidate is None and outcome is None:
        raise LearningError(LEARNING_NOT_FOUND, f"{subject_id} is not a quarantined outcome or candidate")
    review = LearningReview(
        review_id=content_id("rev", subject_id, reviewer_id, verdict, created_at),
        candidate_id=subject_id,
        reviewer_id=reviewer_id,
        reviewer_type=reviewer_type,
        verdict=verdict,
        notes=notes[:2048],
        signed_at=created_at,
        content_hash="",
    )
    payload = review.model_dump(mode="json")
    payload.pop("content_hash", None)
    review.content_hash = canonical_hash(payload)
    persist_review(store, review, created_at=created_at)
    stage: PromotionStage
    if verdict == "approve":
        stage = "approved"
    elif verdict == "reject":
        stage = "rejected"
    else:
        stage = "in_review"
    if candidate is not None and (
        verdict != "approve" or candidate.promotion_stage in {"quarantined", "generalized", "in_review"}
    ):
        candidate.promotion_stage = stage if verdict != "approve" else candidate.promotion_stage
        if verdict == "approve" and candidate.promotion_stage in {"quarantined", "in_review"}:
            candidate.promotion_stage = "approved"
        persist_candidate(store, candidate, created_at=created_at)
    if outcome is not None:
        if verdict == "reject":
            outcome.promotion_stage = "rejected"
        elif verdict == "needs_revision":
            outcome.promotion_stage = "in_review"
        elif outcome.promotion_stage in {"quarantined", "in_review"}:
            outcome.promotion_stage = "approved"
        persist_outcome(store, outcome, created_at=created_at)
    for record in list_queue(store, include_archived=True, include_failed=True):
        if record.subject_id != subject_id:
            continue
        if verdict == "approve":
            record.status = "approved"
        elif verdict == "reject":
            record.status = "rejected"
            record.production_retrievable = False
        else:
            record.status = "in_review"
        from ayran.learning.persist import persist_quarantine

        persist_quarantine(store, record, created_at=created_at)
    return review
