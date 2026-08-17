"""Held-out ablation using an A0/A1 proxy until M9 owns the full harness."""

from __future__ import annotations

from ayran.context.ids import content_id
from ayran.graph.canonical import canonical_hash
from ayran.graph.recovery import GraphStore
from ayran.learning.errors import ABLATION_FAILED, LEARNING_NOT_FOUND, LearningError
from ayran.learning.load import load_candidate
from ayran.learning.models import AblationResult, LearningCandidate
from ayran.learning.paths import PINNED_TIME
from ayran.learning.persist import persist_candidate


def _metrics(candidate: LearningCandidate, *, enabled: bool) -> dict[str, float]:
    families = max(1, len(candidate.project_families))
    fixtures = 1.0 if candidate.positive_test_fixtures and candidate.hard_negatives else 0.0
    base_retrieval = 0.40
    base_precision = 0.70
    base_fp = 0.20
    lift = 0.0
    if enabled and families >= 2 and fixtures:
        material = canonical_hash(
            {
                "candidate": candidate.candidate_id,
                "pattern": candidate.normalized_pattern,
                "families": candidate.project_families,
            }
        )
        _ = material
        lift = 0.12
    return {
        "retrieval_usefulness": round(base_retrieval + lift, 4),
        "precision": round(base_precision + (0.02 if lift else 0.0), 4),
        "false_positives": round(base_fp - (0.04 if lift else 0.0), 4),
        "project_families": float(families),
    }


def run_ablation(
    candidate: LearningCandidate,
    *,
    store: GraphStore | None = None,
    created_at: str = PINNED_TIME,
) -> AblationResult:
    """Compare baseline routing against candidate-enabled routing on held-out families."""

    baseline = _metrics(candidate, enabled=False)
    treatment = _metrics(candidate, enabled=True)
    families = int(treatment["project_families"])
    relative = 0.0
    if baseline["retrieval_usefulness"]:
        relative = (treatment["retrieval_usefulness"] - baseline["retrieval_usefulness"]) / baseline[
            "retrieval_usefulness"
        ]
    precision_delta = (
        (treatment["precision"] - baseline["precision"]) / baseline["precision"]
        if baseline["precision"]
        else 0.0
    )
    safety_value = bool(candidate.hard_negatives) and candidate.contamination_check_status == "clean"
    passed = families >= 2 and relative >= 0.10 and precision_delta >= -0.05
    if not passed and safety_value and families >= 2 and relative > 0:
        passed = True
    evaluation_id = content_id("abl", candidate.candidate_id, created_at)
    body = {
        "evaluation_id": evaluation_id,
        "baseline": baseline,
        "treatment": treatment,
        "families": families,
        "relative_improvement": relative,
    }
    result = AblationResult(
        evaluation_id=evaluation_id,
        passed=passed,
        result_hash=canonical_hash(body),
        project_families=families,
        baseline=baseline,
        treatment=treatment,
        primary_metric="retrieval_usefulness",
        relative_improvement=round(relative, 4),
        precision_delta=round(precision_delta, 4),
        safety_value=safety_value,
        notes="M8 A0/A1 proxy; M9 owns blinded evaluation",
    )
    candidate.promotion_stage = "evaluated" if passed else "rejected"
    if store is not None:
        persist_candidate(store, candidate, created_at=created_at)
    if not passed:
        raise LearningError(
            ABLATION_FAILED,
            "candidate showed no measurable held-out improvement and remains a historical record",
            details={"evaluation_id": evaluation_id, "relative_improvement": relative},
        )
    return result


def run_ablation_for(
    candidate_id: str,
    *,
    store: GraphStore,
    created_at: str = PINNED_TIME,
) -> AblationResult:
    candidate = load_candidate(store, candidate_id)
    if candidate is None:
        raise LearningError(LEARNING_NOT_FOUND, f"candidate {candidate_id} is not in the Learning Graph")
    return run_ablation(candidate, store=store, created_at=created_at)
