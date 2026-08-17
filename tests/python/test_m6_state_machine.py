"""M6 hypothesis state machine: legal edges, evidence, actors, ceilings."""

from __future__ import annotations

from pathlib import Path

import pytest
from ayran.evidence.actors import ACTOR_EVIDENCE, ACTOR_GATE_A, ACTOR_HUMAN, ACTOR_POC
from ayran.evidence.errors import (
    EVIDENCE_CEILING,
    MISSING_EVIDENCE,
    UNAUTHORIZED_ACTOR,
    EvidenceError,
)
from ayran.evidence.state_machine import HypothesisStateMachine, is_legal_edge
from ayran.evidence.types import STATES
from m6_fixtures import SUPPORTED_EVIDENCE, open_store, promote_supported, seed_hypothesis

MACHINE = HypothesisStateMachine()


def test_all_legal_promotions_succeed(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        hyp = seed_hypothesis(store, claim="lead claim about withdraw")
        result = promote_supported(store, hyp["hypothesis_id"])
        assert result["accepted"] is True
        assert result["to"] == "supported"
    finally:
        store.close()


def test_lead_to_supported_without_path_fails(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        hyp = seed_hypothesis(store, claim="lead without target path")
        with pytest.raises(EvidenceError) as raised:
            MACHINE.require(
                hyp,
                "supported",
                actor=ACTOR_EVIDENCE,
                evidence={"preconditions_reachable": True},
            )
        assert raised.value.code == MISSING_EVIDENCE
        assert "path" in str(raised.value.details)
        MACHINE.require(hyp, "supported", actor=ACTOR_EVIDENCE, evidence=SUPPORTED_EVIDENCE)
    finally:
        store.close()


def test_illegal_skip_and_unauthorized_actor() -> None:
    hyp = {"status": "lead", "evidence_grade": "lead", "hypothesis_id": "hyp_01J00000000000000000000001"}
    decision = MACHINE.evaluate(hyp, "observed", actor=ACTOR_POC, evidence={"reproduction_id": "x"})
    assert decision.accepted is False
    assert is_legal_edge("lead", "observed") is False
    with pytest.raises(EvidenceError) as raised:
        MACHINE.require(hyp, "supported", actor=ACTOR_HUMAN, evidence=SUPPORTED_EVIDENCE)
    assert raised.value.code == UNAUTHORIZED_ACTOR


def test_lead_cannot_become_poc_worthy() -> None:
    hyp = {"status": "lead", "evidence_grade": "lead"}
    with pytest.raises(EvidenceError) as raised:
        MACHINE.require(
            hyp,
            "poc_worthy",
            actor=ACTOR_GATE_A,
            evidence={"gate_a_verdict_id": "dav_01J00000000000000000000001", "experiment": {"inputs": ["a"]}},
        )
    assert raised.value.code in {EVIDENCE_CEILING, "TRANSITION_REJECTED"}


def test_demotion_requires_cause() -> None:
    hyp = {"status": "supported", "evidence_grade": "supported"}
    decision = MACHINE.evaluate(hyp, "lead", actor=ACTOR_EVIDENCE, evidence={})
    assert decision.accepted is False
    assert "cause" in decision.missing
    ok = MACHINE.evaluate(
        hyp, "falsified", actor=ACTOR_EVIDENCE, evidence={"killed_dimension": "reentrancy", "counterevidence": "CEI holds"}
    )
    assert ok.accepted is True
    assert ok.demotion is True


def test_legal_matrix_covers_blueprint_edges() -> None:
    expected = {
        ("lead", "supported"),
        ("lead", "falsified"),
        ("lead", "parked"),
        ("supported", "poc_worthy"),
        ("poc_worthy", "observed"),
        ("observed", "defect_pinned"),
        ("defect_pinned", "validated"),
        ("validated", "reported"),
    }
    for edge in expected:
        assert is_legal_edge(*edge), edge
    for state in STATES:
        assert is_legal_edge(state, state) is False
