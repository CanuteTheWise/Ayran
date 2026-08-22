"""M6 Gate A/B structured verdicts. No model calls.

R1: the deterministic decider and the caller-forced verdict channel are deleted
(§5.5). Gate A verdicts arrive only as structurally validated challenger
submissions under a stamped reviewer identity; the three Gate A tests below
assert that new contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from ayran.evidence.errors import EVIDENCE_CEILING, GATE_PRECONDITION, EvidenceError
from ayran.gates.gate_a import run_gate_a
from ayran.gates.gate_b import run_gate_b
from m6_fixtures import (
    CHALLENGER_SUBMISSION_FALSIFIED,
    CHALLENGER_SUBMISSION_MISSING_FACT,
    CHALLENGER_SUBMISSION_POC_WORTHY,
    GATE_B_EXECUTED,
    TRUE_DEFECT_EVIDENCE,
    challenger_gate_a,
    executed_replay_hash,
    open_store,
    promote_supported,
    seed_hypothesis,
)

STAMPED_REVIEWER = {"kind": "gate", "id": "rlm:chd-01j", "version": "1.0.0"}


def test_gate_a_false_positive_falsified(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        hyp = seed_hypothesis(
            store,
            claim="VulnerableVault.withdraw(uint256) sends eth to arbitrary user",
            attack_path=["withdraw"],
            root_cause="arbitrary-send-eth",
        )
        promote_supported(store, hyp["hypothesis_id"])
        from ayran.evidence.load import load_hypothesis

        supported = load_hypothesis(store, hyp["hypothesis_id"])
        assert supported is not None
        result = run_gate_a(
            supported,
            submission=dict(CHALLENGER_SUBMISSION_FALSIFIED),
            created_at=supported["created_at"],
            reviewer=STAMPED_REVIEWER,
        )
        assert result["verdict"] == "falsified"
        assert result["cannot_mark_surface_safe"] is True
        assert result["killed_dimensions"]
        assert result["untried_dimensions"]
        assert result["record"]["gate"] == "A"
        assert result["record"]["resulting_hypothesis_status"] == "falsified"
        assert result["record"]["reviewer"]["id"] == "rlm:chd-01j"
        assert result["record"]["independent_from"] == [supported["hypothesis_id"]]
    finally:
        store.close()


def test_gate_a_true_defect_poc_worthy(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        hyp = seed_hypothesis(
            store,
            claim="ReentrantVault.withdraw is reentrant because the external call happens before balances are zeroed",
            attack_path=["withdraw"],
            root_cause="reentrancy",
            preconditions=["attacker contract with fallback"],
        )
        promote_supported(store, hyp["hypothesis_id"], TRUE_DEFECT_EVIDENCE)
        from ayran.evidence.load import load_hypothesis

        supported = load_hypothesis(store, hyp["hypothesis_id"])
        assert supported is not None
        result = run_gate_a(
            supported,
            submission=dict(CHALLENGER_SUBMISSION_POC_WORTHY),
            created_at=supported["created_at"],
            reviewer=STAMPED_REVIEWER,
        )
        assert result["verdict"] == "poc_worthy"
        assert result["experiment"]["capability"] == "foundry.test"
        assert result["record"]["decision"] == "advance"
    finally:
        store.close()


def test_gate_a_missing_fact(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        hyp = seed_hypothesis(
            store,
            claim="Deployed proxy bytecode may still expose the withdraw path",
            attack_path=["withdraw"],
        )
        promote_supported(store, hyp["hypothesis_id"])
        result = challenger_gate_a(
            store, hyp["hypothesis_id"], dict(CHALLENGER_SUBMISSION_MISSING_FACT)
        )
        assert result["verdict"] == "needs_missing_fact"
        assert result["record"]["reviewer"]["kind"] == "gate"
    finally:
        store.close()


def test_gate_a_rejects_lead() -> None:
    with pytest.raises(EvidenceError) as raised:
        run_gate_a({"status": "lead", "evidence_grade": "lead", "claim": "x", "hypothesis_id": "hyp_01J00000000000000000000001"})
    assert raised.value.code in {GATE_PRECONDITION, EVIDENCE_CEILING}


def test_gate_b_unspecified_reformulates() -> None:
    hyp = {
        "status": "observed",
        "evidence_grade": "observed",
        "hypothesis_id": "hyp_01J00000000000000000000001",
        "run_id": "run_01J00000000000000000000001",
        "created_at": "2026-08-12T12:00:00Z",
        "target_identity": {
            "target_id": "tgt_01J00000000000000000000001",
            "source_tree_hash": "sha256:" + "d" * 64,
            "scope_id": "scp_01J00000000000000000000001",
            "commit": "1" * 40,
        },
        "claim": "reentrancy",
    }
    result = run_gate_b(hyp, obligations={})
    assert result["verdict"] == "needs_reformulation"


def test_gate_b_clean_replay_pins_defect() -> None:
    hyp = {
        "status": "observed",
        "evidence_grade": "observed",
        "hypothesis_id": "hyp_01J00000000000000000000001",
        "run_id": "run_01J00000000000000000000001",
        "created_at": "2026-08-12T12:00:00Z",
        "target_identity": {
            "target_id": "tgt_01J00000000000000000000001",
            "source_tree_hash": "sha256:" + "d" * 64,
            "scope_id": "scp_01J00000000000000000000001",
            "commit": "1" * 40,
        },
        "claim": "reentrancy",
    }
    result = run_gate_b(hyp, obligations=GATE_B_EXECUTED)
    assert result["verdict"] == "defect_pinned"
    assert result["record"]["resulting_hypothesis_status"] == "defect_pinned"
    replay = run_gate_b(
        hyp,
        obligations=GATE_B_EXECUTED,
        poc={
            "status": "succeeded",
            "result_hash": executed_replay_hash(),
            "replay_hash": executed_replay_hash(),
            "replay_matched": True,
        },
    )
    assert replay["obligations"]["clean_replay"]["passed"] is True
