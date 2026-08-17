"""Promotion pipeline: quarantine → review → generalize → fixtures → contamination → ablation → release."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ayran.context.ids import content_id
from ayran.graph.recovery import GraphStore
from ayran.learning.ablation import run_ablation
from ayran.learning.contamination import contamination_check
from ayran.learning.errors import (
    DIRECT_MUTATION_DENIED,
    FIXTURES_REQUIRED,
    LEARNING_NOT_FOUND,
    PROMOTION_DENIED,
    REDACTION_INCOMPLETE,
    REVIEW_INCOMPLETE,
    LearningError,
)
from ayran.learning.fixtures import generate_fixtures
from ayran.learning.load import load_candidate, load_reviews
from ayran.learning.models import AblationResult, LearningCandidate, PromotionRelease, RoutingPolicy
from ayran.learning.paths import PINNED_TIME, default_learning_root
from ayran.learning.persist import persist_candidate, persist_promotion, persist_routing_policy
from ayran.learning.release import (
    baseline_routing_policy,
    load_current,
    publish_release,
    write_routing_policy,
)

REQUIRED_GATES = (
    "two_independent_reviews",
    "deterministic_generalization",
    "positive_and_hard_negative_fixtures",
    "no_sealed_holdout_contamination",
    "held_out_improvement",
    "provenance_rights",
    "bounded_cost",
    "rollback_plan",
)


def _independent_approvals(store: GraphStore, candidate: LearningCandidate) -> list[str]:
    reviews = load_reviews(store, candidate.candidate_id)
    if not reviews:
        reviews = load_reviews(store, candidate.outcome_ref)
    approved = [item for item in reviews if item.verdict == "approve"]
    unique: dict[str, str] = {}
    for item in approved:
        unique[item.reviewer_id] = item.reviewer_type
    if len(unique) < 2:
        return list(unique)
    types = set(unique.values())
    if "human" in types and ("independent_agent" in types or "human" in types):
        return list(unique)
    return list(unique)


def _gate_failures(store: GraphStore, candidate: LearningCandidate) -> list[str]:
    failures: list[str] = []
    approvals = _independent_approvals(store, candidate)
    if len(approvals) < 2:
        failures.append("two_independent_reviews")
    if candidate.target_secret_redaction_status == "incomplete":
        failures.append("deterministic_generalization")
    if not candidate.positive_test_fixtures or not candidate.hard_negatives:
        failures.append("positive_and_hard_negative_fixtures")
    if candidate.contamination_check_status != "clean":
        failures.append("no_sealed_holdout_contamination")
    if not candidate.rights.license_or_terms:
        failures.append("provenance_rights")
    if not candidate.bounded_cost:
        failures.append("bounded_cost")
    return failures


def promote_candidate(
    candidate: LearningCandidate,
    *,
    store: GraphStore,
    learning_root: Path | str | None = None,
    created_at: str = PINNED_TIME,
    holdouts: list[dict[str, Any]] | None = None,
    routing_policy: RoutingPolicy | None = None,
) -> PromotionRelease:
    """Run remaining promotion gates. Never mutates Global production current."""

    if str(store.stream.get("namespace") or "") == "global":
        raise LearningError(DIRECT_MUTATION_DENIED, "a run cannot promote directly into Global production")
    if candidate.target_secret_redaction_status == "incomplete":
        raise LearningError(REDACTION_INCOMPLETE, "candidate leaked or retained target secrets")
    if not candidate.positive_test_fixtures or not candidate.hard_negatives:
        generate_fixtures(candidate, store=store, created_at=created_at)
    if not candidate.positive_test_fixtures or not candidate.hard_negatives:
        raise LearningError(FIXTURES_REQUIRED, "positive and hard-negative fixtures are required")
    contamination_check(candidate, store=store, holdouts=holdouts, created_at=created_at)
    ablation: AblationResult = run_ablation(candidate, store=store, created_at=created_at)
    failures = _gate_failures(store, candidate)
    if "held_out_improvement" not in failures and not ablation.passed:
        failures.append("held_out_improvement")
    if failures:
        candidate.promotion_stage = "rejected"
        persist_candidate(store, candidate, created_at=created_at)
        raise LearningError(
            PROMOTION_DENIED,
            "promotion gates failed: " + ", ".join(failures),
            details={"failed_gates": failures},
        )
    if len(_independent_approvals(store, candidate)) < 2:
        raise LearningError(
            REVIEW_INCOMPLETE,
            "promotion requires two-person or user-plus-independent-agent review",
        )
    root = Path(learning_root) if learning_root else default_learning_root()
    previous = load_current(root)
    prior = str(previous.get("release_id") if previous else "")
    if not prior:
        baseline = PromotionRelease(
            release_id="ayran-learning-baseline-v1",
            created_at=created_at,
            candidates=[],
            prior_pointer="",
            rollback_pointer="ayran-learning-baseline-v1",
            signed_at=created_at,
            action="promote",
        )
        publish_release(root, baseline, candidates=[], switch_pointer=True)
        prior = baseline.release_id
    release_id = content_id("rel", candidate.candidate_id, created_at, candidate.content_hash)
    policy = routing_policy or baseline_routing_policy(created_at=created_at)
    policy.status = "active"
    policy.knowledge_records = [candidate.candidate_id]
    policy.prior_pointer = prior
    policy.rollback_pointer = prior or policy.policy_id
    write_routing_policy(root, policy)
    persist_routing_policy(store, policy, created_at=created_at)
    release = PromotionRelease(
        release_id=release_id,
        created_at=created_at,
        candidates=[candidate.candidate_id],
        prior_pointer=prior,
        rollback_pointer=prior,
        signed_at=created_at,
        ablation_results=[ablation],
        reviewer_signatures=_independent_approvals(store, candidate),
        routing_policy_id=policy.policy_id,
        action="promote",
        corpus_pin=prior,
    )
    published = publish_release(
        root,
        release,
        candidates=[candidate.model_dump(mode="json")],
        switch_pointer=True,
    )
    candidate.promotion_stage = "released"
    candidate.trust_class = "adjudicated"
    persist_candidate(store, candidate, created_at=created_at)
    persist_promotion(store, published, created_at=created_at)
    return published


def promote(
    candidate_id: str,
    *,
    store: GraphStore,
    learning_root: Path | str | None = None,
    created_at: str = PINNED_TIME,
    holdouts: list[dict[str, Any]] | None = None,
) -> PromotionRelease:
    candidate = load_candidate(store, candidate_id)
    if candidate is None:
        raise LearningError(LEARNING_NOT_FOUND, f"candidate {candidate_id} is not in the Learning Graph")
    return promote_candidate(
        candidate,
        store=store,
        learning_root=learning_root,
        created_at=created_at,
        holdouts=holdouts,
    )
