"""Shared M8 Learning Graph helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ayran.context.ids import content_id
from ayran.graph.namespaces import TargetNamespace
from ayran.graph.recovery import GraphStore
from ayran.learning.capture import capture_outcome
from ayran.learning.fixtures import generate_fixtures
from ayran.learning.generalize import generalize_outcome
from ayran.learning.models import LearningCandidate, LearningOutcome
from ayran.learning.paths import PINNED_TIME
from ayran.learning.quarantine import submit_for_review
from ayran.learning.review import record_review
from m5_fixtures import RUN_ID, TARGET_IDENTITY, TARGET_KEY

HUMAN = content_id("act", "human-reviewer")
AGENT = content_id("act", "independent-agent")
CLAIM = (
    "reentrancy oracle invariant violation: share accounting updates balances after an external call"
)


def open_store(tmp_path: Path) -> GraphStore:
    namespace = TargetNamespace(
        tmp_path / "graph",
        RUN_ID,
        TARGET_IDENTITY,
        TARGET_KEY,
        allow_unsafe_filesystem=True,
    )
    return GraphStore(namespace.root, namespace.stream, allow_unsafe_filesystem=True)


def write_stream(tmp_path: Path, store: GraphStore) -> tuple[Path, Path]:
    root = store.root
    stream_path = tmp_path / "stream.json"
    stream_path.write_text(
        __import__("json").dumps(store.stream),
        encoding="utf-8",
    )
    return root, stream_path


def graph_args(tmp_path: Path, store: GraphStore) -> list[str]:
    root, stream = write_stream(tmp_path, store)
    return [
        "--graph-root",
        str(root),
        "--stream",
        str(stream),
        "--allow-unsafe-filesystem",
        "--learning-root",
        str(tmp_path / "learning"),
    ]


def capture_sample(
    store: GraphStore,
    *,
    claim: str = CLAIM,
    outcome_type: str = "accepted",
    extras: dict[str, Any] | None = None,
) -> LearningOutcome:
    hypothesis = {
        "claim": claim,
        "origin": "model_novel",
        "novelty": "novel",
        "impact_kind": "integrity_violation",
        "target_identity": TARGET_IDENTITY,
        **(extras or {}),
    }
    outcome = capture_outcome(
        RUN_ID,
        outcome_type,
        content_id("hyp", claim[:24], outcome_type),
        [{"gate": "A", "decision": "poc_worthy"}],
        [{"capability_id": "foundry.test", "stdout_hash": "sha256:" + "a" * 64, "tool_name": "foundry", "tool_version": "1.7.1"}],
        ["sha256:" + "b" * 64],
        store=store,
        hypothesis=hypothesis,
        created_at=PINNED_TIME,
    )
    submit_for_review(outcome.outcome_id, store=store, outcome=outcome, created_at=PINNED_TIME)
    return outcome


def approve_twice(store: GraphStore, subject_id: str) -> None:
    record_review(
        subject_id,
        reviewer_id=HUMAN,
        reviewer_type="human",
        verdict="approve",
        notes="portable mechanism",
        store=store,
        created_at=PINNED_TIME,
    )
    record_review(
        subject_id,
        reviewer_id=AGENT,
        reviewer_type="independent_agent",
        verdict="approve",
        notes="independent confirmation",
        store=store,
        created_at=PINNED_TIME,
    )


def ready_candidate(store: GraphStore, *, claim: str = CLAIM) -> LearningCandidate:
    outcome = capture_sample(store, claim=claim)
    approve_twice(store, outcome.outcome_id)
    candidate = generalize_outcome(outcome, store=store, created_at=PINNED_TIME, require_review=True)
    generate_fixtures(candidate, store=store, created_at=PINNED_TIME)
    return candidate
