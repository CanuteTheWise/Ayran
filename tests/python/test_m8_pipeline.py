"""M8 quarantine, generalization, fixtures, contamination, ablation, promote, rollback."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from ayran.context.queries import OntologyQueries
from ayran.learning.ablation import run_ablation
from ayran.learning.contamination import contamination_check
from ayran.learning.errors import (
    ABLATION_FAILED,
    CONTAMINATION_BLOCKED,
    PROMOTION_DENIED,
    LearningError,
)
from ayran.learning.generalize import generalize_outcome
from ayran.learning.load import load_candidates
from ayran.learning.paths import PINNED_TIME
from ayran.learning.promote import promote_candidate
from ayran.learning.quarantine import (
    archive_expired,
    list_queue,
    record_is_production_retrievable,
)
from ayran.learning.release import load_current
from ayran.learning.rollback import rollback
from m8_fixtures import approve_twice, capture_sample, open_store, ready_candidate


def test_quarantine_queue_and_ttl_archive(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        outcome = capture_sample(store)
        queued = list_queue(store)
        assert queued
        assert queued[0].subject_id == outcome.outcome_id
        assert queued[0].production_retrievable is False
        archived = archive_expired(store, now="2026-09-20T00:00:00Z", ttl_days=30)
        assert outcome.outcome_id in archived
        remaining = list_queue(store, include_archived=False)
        assert all(item.subject_id != outcome.outcome_id for item in remaining)
        failed = list_queue(store, include_archived=True)
        assert any(item.status == "archived" for item in failed)
        assert record_is_production_retrievable(store, outcome.outcome_id) is False
    finally:
        store.close()


def test_generalize_is_deterministic_and_strips_identifiers(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        outcome = capture_sample(
            store,
            claim="AcmeVault reentrancy on 0xabcabcabcabcabcabcabcabcabcabcabcabcabca after FakeToken transfer",
        )
        approve_twice(store, outcome.outcome_id)
        first = generalize_outcome(outcome, store=store, seed="0")
        second = generalize_outcome(outcome, seed="0", require_review=False)
        assert first.candidate_id == second.candidate_id
        assert first.content_hash == second.content_hash
        assert "0xabcabcabcabcabcabcabcabcabcabcabcabcabca" not in first.normalized_pattern
        assert "acmevault" not in first.normalized_pattern.lower()
        assert "faketoken" not in first.normalized_pattern.lower()
        assert first.trust_class == "model_observation"
        assert first.target_secret_redaction_status in {"clean", "redacted"}
    finally:
        store.close()


def test_fixture_generation_positive_and_hard_negative(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        candidate = ready_candidate(store)
        assert candidate.positive_test_fixtures
        assert candidate.hard_negatives
        from ayran.learning.fixtures import generate_fixtures

        positive, negative = generate_fixtures(candidate)
        assert "pragma solidity" in positive.code
        assert negative.why_safe
        assert "nonReentrant" in negative.code
        assert "after the external call" in negative.distinction
    finally:
        store.close()


def test_contamination_blocks_sealed_holdout(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        candidate = ready_candidate(store)
        holdouts = [
            {
                "record_id": "sealed-1",
                "root_cause": candidate.root_cause,
                "project_family": candidate.project_families[0],
                "near_duplicate_lineage": "sealed-holdout",
                "forced_overlap": True,
            }
        ]
        with pytest.raises(LearningError) as raised:
            contamination_check(candidate, store=store, holdouts=holdouts)
        assert raised.value.code == CONTAMINATION_BLOCKED
        loaded = load_candidates(store)
        assert loaded[0].contamination_check_status == "overlap"
        assert loaded[0].promotion_stage == "rejected"
        assert record_is_production_retrievable(store, loaded[0].candidate_id) is False
    finally:
        store.close()


def test_ablation_requires_multi_family_improvement(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        weak = capture_sample(store, claim="unspecified observation")
        approve_twice(store, weak.outcome_id)
        from ayran.learning.generalize import generalize_outcome as gen

        candidate = gen(weak, store=store, require_review=True)
        with pytest.raises(LearningError) as raised:
            run_ablation(candidate, store=store)
        assert raised.value.code == ABLATION_FAILED
        strong = ready_candidate(store)
        contamination_check(strong, store=store, holdouts=[])
        result = run_ablation(strong, store=store)
        assert result.passed is True
        assert result.project_families >= 2
        assert result.relative_improvement >= 0.10
    finally:
        store.close()


def test_promotion_and_atomic_rollback(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    learning_root = tmp_path / "learning"
    try:
        candidate = ready_candidate(store)
        released = promote_candidate(
            candidate,
            store=store,
            learning_root=learning_root,
            holdouts=[],
            created_at=PINNED_TIME,
        )
        assert released.content_hash.startswith("sha256:")
        assert released.signature == released.content_hash
        pointer = load_current(learning_root)
        assert pointer is not None
        assert pointer["release_id"] == released.release_id
        promoted = load_candidates(store, released_only=True)
        assert promoted and promoted[0].candidate_id == candidate.candidate_id
        queries = OntologyQueries(store=store)
        lessons = asyncio.run(queries.get_promoted_lessons())
        assert lessons
        policy = asyncio.run(queries.get_routing_policy())
        assert policy.get("policy_id") != "m8-stub"
        assert "policy" not in policy or policy.get("policy") != "m8-stub"
        rolled = rollback(released.release_id, store=store, learning_root=learning_root)
        restored = load_current(learning_root)
        assert restored is not None
        assert restored["release_id"] == rolled.restored_pointer
        assert rolled.historical_pins_retained is True
        still = load_candidates(store, released_only=True)
        assert still
    finally:
        store.close()


def test_direct_promotion_without_reviews_denied(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        outcome = capture_sample(store)
        candidate = generalize_outcome(outcome, require_review=False, store=store)
        from ayran.learning.fixtures import generate_fixtures

        generate_fixtures(candidate, store=store)
        with pytest.raises(LearningError) as raised:
            promote_candidate(candidate, store=store, learning_root=tmp_path / "learning", holdouts=[])
        assert raised.value.code in {PROMOTION_DENIED, "REVIEW_INCOMPLETE"}
    finally:
        store.close()
