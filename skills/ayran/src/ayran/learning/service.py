"""Sidecar/CLI facade for the Learning Graph. Journal writes go through GraphStore."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ayran.graph.recovery import GraphStore
from ayran.learning.ablation import run_ablation_for
from ayran.learning.capture import capture_outcome, capture_run_outcomes
from ayran.learning.contamination import check_candidate
from ayran.learning.errors import LearningError
from ayran.learning.fixtures import generate_fixtures_for
from ayran.learning.generalize import generalize
from ayran.learning.load import (
    load_candidates,
    load_routing_policies,
)
from ayran.learning.models import OutcomeType
from ayran.learning.paths import BASELINE_ROUTING_POLICY, PINNED_TIME, default_learning_root
from ayran.learning.promote import promote
from ayran.learning.quarantine import archive_expired, list_queue, queue_payload, submit_for_review
from ayran.learning.release import load_current, load_routing_policy
from ayran.learning.review import record_review
from ayran.learning.rollback import rollback as rollback_release


def _root(learning_root: Path | str | None) -> Path:
    if learning_root is None:
        return default_learning_root()
    return Path(learning_root)


def capture(
    run_id: str,
    *,
    store: GraphStore | None = None,
    outcome_type: OutcomeType | str = "adjudicated",
    hypothesis_id: str = "",
    gate_verdicts: list[dict[str, Any]] | None = None,
    tool_runs: list[dict[str, Any]] | None = None,
    artifacts: list[Any] | None = None,
    created_at: str = PINNED_TIME,
) -> dict[str, Any]:
    if store is not None and not hypothesis_id:
        return capture_run_outcomes(store, run_id=run_id, created_at=created_at)
    if not hypothesis_id:
        raise LearningError("LEARNING_NOT_FOUND", "capture requires a hypothesis_id or a graph store")
    outcome = capture_outcome(
        run_id,
        outcome_type,
        hypothesis_id,
        gate_verdicts or [],
        tool_runs or [],
        artifacts or [],
        store=store,
        created_at=created_at,
    )
    if store is not None:
        submit_for_review(outcome.outcome_id, store=store, outcome=outcome, created_at=created_at)
    return outcome.model_dump(mode="json")


def submit_review(outcome_id: str, *, store: GraphStore, created_at: str = PINNED_TIME) -> dict[str, Any]:
    record = submit_for_review(outcome_id, store=store, created_at=created_at)
    return record.model_dump(mode="json")


def review(
    subject_id: str,
    *,
    store: GraphStore,
    reviewer_id: str,
    reviewer_type: str,
    verdict: str,
    notes: str = "",
    created_at: str = PINNED_TIME,
) -> dict[str, Any]:
    mapped_verdict = verdict.replace("-", "_")
    if mapped_verdict not in {"approve", "reject", "needs_revision"}:
        raise LearningError("CONTRACT_INVALID", "verdict must be approve, reject, or needs_revision")
    if reviewer_type not in {"human", "independent_agent"}:
        raise LearningError("CONTRACT_INVALID", "reviewer_type must be human or independent_agent")
    recorded = record_review(
        subject_id,
        reviewer_id=reviewer_id,
        reviewer_type=reviewer_type,  # type: ignore[arg-type]
        verdict=mapped_verdict,  # type: ignore[arg-type]
        notes=notes,
        store=store,
        created_at=created_at,
    )
    return recorded.model_dump(mode="json")


def generalize_outcome(outcome_id: str, *, store: GraphStore, seed: str = "0") -> dict[str, Any]:
    return generalize(outcome_id, store=store, seed=seed).model_dump(mode="json")


def generate_test_fixtures(candidate_id: str, *, store: GraphStore) -> dict[str, Any]:
    return generate_fixtures_for(candidate_id, store=store)


def contamination_check(candidate_id: str, *, store: GraphStore, holdouts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return check_candidate(candidate_id, store=store, holdouts=holdouts)


def run_ablation(candidate_id: str, *, store: GraphStore) -> dict[str, Any]:
    return run_ablation_for(candidate_id, store=store).model_dump(mode="json")


def promote_candidate(
    candidate_id: str,
    *,
    store: GraphStore,
    learning_root: Path | str | None = None,
    holdouts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return promote(
        candidate_id,
        store=store,
        learning_root=_root(learning_root),
        holdouts=holdouts,
    ).model_dump(mode="json")


def rollback(
    release_id: str,
    *,
    store: GraphStore | None = None,
    learning_root: Path | str | None = None,
) -> dict[str, Any]:
    return rollback_release(release_id, store=store, learning_root=_root(learning_root)).model_dump(mode="json")


def learning_status(
    *,
    store: GraphStore | None = None,
    learning_root: Path | str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    root = _root(learning_root)
    pointer = load_current(root)
    policy = load_routing_policy(root)
    queue: list[dict[str, Any]] = []
    released: list[str] = []
    if store is not None:
        if now:
            archive_expired(store, now=now)
        queue = [item.model_dump(mode="json") for item in list_queue(store, include_archived=True)]
        released = [
            item.candidate_id for item in load_candidates(store, released_only=True)
        ]
    return {
        "schema_version": "1.0.0",
        "active_release": pointer,
        "routing_policy": policy.model_dump(mode="json"),
        "queue": queue,
        "released_candidates": released,
        "production_mutation": False,
    }


def routing_policy_status(
    policy_id: str | None = None,
    *,
    store: GraphStore | None = None,
    learning_root: Path | str | None = None,
) -> dict[str, Any]:
    root = _root(learning_root)
    policy = load_routing_policy(root, policy_id)
    extras: list[dict[str, Any]] = []
    if store is not None:
        extras = [item.model_dump(mode="json") for item in load_routing_policies(store)]
    return {
        "schema_version": "1.0.0",
        "policy_id": policy.policy_id,
        "policy": policy.model_dump(mode="json"),
        "graph_policies": extras,
        "baseline": policy.policy_id == BASELINE_ROUTING_POLICY,
    }


def queue_status(store: GraphStore) -> dict[str, Any]:
    return queue_payload(store)


def promoted_lessons(store: GraphStore, tags: list[str] | None = None) -> list[dict[str, Any]]:
    lessons = []
    wanted = {item.lower() for item in (tags or [])}
    for candidate in load_candidates(store, released_only=True):
        predicates = {item.lower() for item in candidate.applicability_predicates}
        families = {item.lower() for item in candidate.project_families}
        if wanted and not (wanted & predicates or wanted & families):
            continue
        lessons.append(
            {
                "id": candidate.candidate_id,
                "mechanism": candidate.generalized_mechanism,
                "pattern": candidate.normalized_pattern,
                "applicability_predicates": list(candidate.applicability_predicates),
                "trust_class": candidate.trust_class,
                "promotion_stage": candidate.promotion_stage,
                "project_families": list(candidate.project_families),
                "hard_negatives": list(candidate.hard_negatives),
            }
        )
    return sorted(lessons, key=lambda item: str(item["id"]))
