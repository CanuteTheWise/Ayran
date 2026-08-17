"""Deterministic generalization of quarantined outcomes into portable candidates."""

from __future__ import annotations

import re
from typing import Any

from ayran.context.ids import content_id
from ayran.graph.canonical import canonical_hash
from ayran.graph.recovery import GraphStore
from ayran.learning.errors import (
    LEARNING_NOT_FOUND,
    REDACTION_INCOMPLETE,
    REVIEW_INCOMPLETE,
    LearningError,
)
from ayran.learning.load import load_outcome, load_reviews
from ayran.learning.models import LearningCandidate, LearningOutcome, RightsRecord
from ayran.learning.paths import PINNED_TIME
from ayran.learning.persist import persist_candidate, persist_outcome

ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
PROJECTISH_RE = re.compile(r"\b(?:[A-Z][a-z]+(?:Token|Vault|Pool|Router|Pair|Protocol|DAO|NFT)+)\b")
DEFAULT_DENYLIST = frozenset(
    {
        "vulnerablevault",
        "acme",
        "contoso",
        "faketoken",
        "testdao",
        "projectx",
        "usdc",
        "weth",
        "uniswap",
    }
)


def _normalize_mechanism(text: str) -> str:
    lowered = text.strip().lower()
    lowered = ADDRESS_RE.sub("<address>", lowered)
    lowered = re.sub(r"\b[a-z0-9]{8,}\.eth\b", "<ens>", lowered)
    lowered = re.sub(r"\s+", " ", lowered)
    return lowered[:2048]


def _strip_denylist(text: str, extra: frozenset[str]) -> tuple[str, list[str]]:
    hits: list[str] = []
    result = text
    for term in sorted(DEFAULT_DENYLIST | extra, key=len, reverse=True):
        if not term:
            continue
        pattern = re.compile(re.escape(term), re.IGNORECASE)
        if pattern.search(result):
            hits.append(term)
            result = pattern.sub("<project>", result)
    result = PROJECTISH_RE.sub("<component>", result)
    result = ADDRESS_RE.sub("<address>", result)
    return result, hits


def _families(text: str) -> list[str]:
    families: list[str] = []
    mapping = (
        ("reentrancy", "reentrancy"),
        ("oracle", "oracle"),
        ("authorization", "access-control"),
        ("access control", "access-control"),
        ("rounding", "rounding"),
        ("invariant", "invariant"),
        ("flash", "flash-loan"),
        ("signature", "signature"),
        ("proxy", "proxy"),
        ("erc4626", "erc4626"),
        ("erc20", "erc20"),
    )
    lowered = text.lower()
    for needle, family in mapping:
        if needle in lowered and family not in families:
            families.append(family)
    if not families:
        families.append("generic-solidity")
    return families[:8]


def generalize_outcome(
    outcome: LearningOutcome,
    *,
    seed: str = "0",
    extra_denylist: frozenset[str] | None = None,
    require_review: bool = True,
    store: GraphStore | None = None,
    created_at: str = PINNED_TIME,
) -> LearningCandidate:
    """Same outcome + seed yields the same candidate. Target secrets are stripped."""

    if require_review and store is not None:
        approvals = [
            item
            for item in load_reviews(store, outcome.outcome_id)
            if item.verdict == "approve"
        ]
        if len({item.reviewer_id for item in approvals}) < 1:
            raise LearningError(
                REVIEW_INCOMPLETE,
                "generalization requires at least one independent approval of the quarantined outcome",
            )
    extra = extra_denylist or frozenset()
    source = " ".join(
        part
        for part in (
            outcome.adjudication,
            outcome.claim_digest,
            outcome.origin,
            outcome.false_positive_reason,
        )
        if part
    )
    stripped, hits = _strip_denylist(source, extra)
    normalized = _normalize_mechanism(stripped)
    if not normalized or normalized in {"<project>", "<address>", "<component>"}:
        raise LearningError(
            REDACTION_INCOMPLETE,
            "pattern cannot be fully redacted without losing semantic content; remains quarantined",
        )
    redaction: Any = "redacted" if hits or ADDRESS_RE.search(source) else "clean"
    if "<project>" in normalized and len(normalized.replace("<project>", "").strip()) < 8:
        raise LearningError(
            REDACTION_INCOMPLETE,
            "redaction would remove the mechanism; candidate stays in human review",
        )
    families = _families(normalized)
    predicates = ["language:solidity", *[f"family:{item}" for item in families]]
    unsigned = {
        "outcome_ref": outcome.outcome_id,
        "normalized_pattern": normalized,
        "seed": seed,
        "families": families,
    }
    candidate_id = content_id("cand", outcome.outcome_id, seed, canonical_hash(unsigned))
    candidate = LearningCandidate(
        candidate_id=candidate_id,
        created_at=created_at,
        outcome_ref=outcome.outcome_id,
        generalized_mechanism=normalized[:512],
        normalized_pattern=normalized,
        applicability_predicates=predicates,
        hard_negatives=[],
        positive_test_fixtures=[],
        target_secret_redaction_status=redaction,
        contamination_check_status="unknown",
        promotion_stage="generalized",
        trust_class="model_observation",
        project_families=families,
        root_cause=families[0],
        seed=seed,
        content_hash="",
        rights=RightsRecord(reviewed=False),
        provenance_attached=True,
        bounded_cost=True,
    )
    payload = candidate.model_dump(mode="json")
    payload.pop("content_hash", None)
    candidate.content_hash = canonical_hash(payload)
    if store is not None:
        persist_candidate(store, candidate, created_at=created_at)
        outcome.promotion_stage = "generalized"
        persist_outcome(store, outcome, created_at=created_at)
    return candidate


def generalize(
    outcome_id: str,
    *,
    store: GraphStore,
    seed: str = "0",
    created_at: str = PINNED_TIME,
) -> LearningCandidate:
    outcome = load_outcome(store, outcome_id)
    if outcome is None:
        raise LearningError(LEARNING_NOT_FOUND, f"outcome {outcome_id} is not in the Learning Graph")
    return generalize_outcome(outcome, seed=seed, store=store, created_at=created_at)
