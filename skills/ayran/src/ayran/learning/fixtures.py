"""Positive and hard-negative fixtures for Learning candidates."""

from __future__ import annotations

from ayran.context.ids import content_id
from ayran.graph.canonical import canonical_hash
from ayran.graph.recovery import GraphStore
from ayran.learning.errors import LEARNING_NOT_FOUND, LearningError
from ayran.learning.load import load_candidate
from ayran.learning.models import LearningCandidate, TestFixture
from ayran.learning.paths import PINNED_TIME
from ayran.learning.persist import persist_candidate

POSITIVE_TEMPLATE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Positive fixture for generalized mechanism: {mechanism}
contract Positive{suffix} {{
    mapping(address => uint256) public balances;
    bool private locked;

    function deposit() external payable {{
        balances[msg.sender] += msg.value;
    }}

    function withdraw() external {{
        // Vulnerable pattern under test: missing guard around external call.
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{{value: amount}}("");
        require(ok, "send");
        balances[msg.sender] = 0;
        locked = locked;
    }}
}}
"""

HARD_NEGATIVE_TEMPLATE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Hard negative: superficially similar, actually safe.
contract Safe{suffix} {{
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {{
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }}

    function deposit() external payable {{
        balances[msg.sender] += msg.value;
    }}

    function withdraw() external nonReentrant {{
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{{value: amount}}("");
        require(ok, "send");
    }}
}}
"""


def _suffix(candidate_id: str) -> str:
    compact = "".join(ch for ch in candidate_id if ch.isalnum())[-8:]
    return compact[:1].upper() + compact[1:].lower() if compact else "Fx"


def generate_fixtures(
    candidate: LearningCandidate,
    *,
    store: GraphStore | None = None,
    created_at: str = PINNED_TIME,
) -> tuple[TestFixture, TestFixture]:
    suffix = _suffix(candidate.candidate_id)
    mechanism = candidate.generalized_mechanism or candidate.normalized_pattern
    positive_code = POSITIVE_TEMPLATE.format(mechanism=mechanism[:180], suffix=suffix)
    negative_code = HARD_NEGATIVE_TEMPLATE.format(suffix=suffix)
    positive = TestFixture(
        fixture_id=content_id("fix", candidate.candidate_id, "positive"),
        fixture_type="positive",
        code=positive_code,
        mechanism=mechanism,
        content_hash=canonical_hash({"type": "positive", "code": positive_code}),
    )
    negative = TestFixture(
        fixture_id=content_id("fix", candidate.candidate_id, "hard_negative"),
        fixture_type="hard_negative",
        code=negative_code,
        why_safe="checks-effects-interactions plus a nonReentrant guard; the external call cannot re-enter withdraw",
        distinction="the positive fixture updates balances after the external call; the negative zeros storage first and locks",
        mechanism=mechanism,
        content_hash=canonical_hash({"type": "hard_negative", "code": negative_code}),
    )
    candidate.positive_test_fixtures = [positive.fixture_id]
    candidate.hard_negatives = [negative.fixture_id]
    candidate.promotion_stage = "fixtures_ready"
    payload = candidate.model_dump(mode="json")
    payload.pop("content_hash", None)
    candidate.content_hash = canonical_hash(payload)
    if store is not None:
        persist_candidate(store, candidate, created_at=created_at)
    return positive, negative


def generate_fixtures_for(
    candidate_id: str,
    *,
    store: GraphStore,
    created_at: str = PINNED_TIME,
) -> dict[str, object]:
    candidate = load_candidate(store, candidate_id)
    if candidate is None:
        raise LearningError(LEARNING_NOT_FOUND, f"candidate {candidate_id} is not in the Learning Graph")
    positive, negative = generate_fixtures(candidate, store=store, created_at=created_at)
    return {
        "schema_version": "1.0.0",
        "candidate_id": candidate.candidate_id,
        "positive": positive.model_dump(mode="json"),
        "hard_negative": negative.model_dump(mode="json"),
    }
