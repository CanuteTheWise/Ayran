"""M6 dedup, impact, and versioned severity."""

from __future__ import annotations

from pathlib import Path

from ayran.evidence.dedup import check_duplicates, classify_pair
from ayran.evidence.impact import assess_impact
from ayran.evidence.severity import assess_severity
from m6_fixtures import open_store, seed_hypothesis


def test_exact_span_duplicate_and_variant_preserved() -> None:
    left = {
        "hypothesis_id": "hyp_01J00000000000000000000001",
        "claim": "reentrancy in withdraw",
        "attack_path": ["withdraw", "fallback"],
        "source_spans": ["ReentrantVault.sol:12"],
        "preconditions": [{"description": "attacker contract"}],
        "target_entities": ["state"],
        "root_cause": "call-before-zero",
        "impact_premise": {"kind": "asset_theft"},
        "target_identity": {"commit": "1" * 40},
    }
    same = dict(left)
    same["hypothesis_id"] = "hyp_01J00000000000000000000002"
    pair = classify_pair(left, same)
    assert pair["disposition"] == "duplicate_known_issue"
    assert pair["deleted"] is False
    variant = dict(left)
    variant["hypothesis_id"] = "hyp_01J00000000000000000000003"
    variant["attack_path"] = ["withdraw", "token-hook"]
    variant["source_spans"] = ["ReentrantVault.sol:99"]
    classified = classify_pair(left, variant)
    assert classified["disposition"] == "variant"
    assert classified["same_root_cause"] is True
    result = check_duplicates(same, [left])
    assert result["duplicate_of"] == left["hypothesis_id"]
    assert result["deleted"] is False


def test_impact_records_assumptions_and_bounds() -> None:
    hyp = {
        "hypothesis_id": "hyp_01J00000000000000000000001",
        "impact_premise": {"kind": "asset_theft", "description": "theft", "upper_bound": None},
        "target_identity": {"commit": "1" * 40, "source_tree_hash": "sha256:" + "d" * 64},
    }
    record = assess_impact(hyp, assumptions={"asset_price": "2", "unit_loss": "10", "repetitions": 3})
    assert record["profit_loss"]["lower_bound"] == "20"
    assert record["profit_loss"]["upper_bound"] == "60"
    assert any(item.startswith("asset_price=") for item in record["assumptions"])
    assert record["finding_impact"]["kind"] == "theft"


def test_severity_cites_policy_and_ambiguity() -> None:
    impact = assess_impact(
        {
            "hypothesis_id": "hyp_01J00000000000000000000001",
            "impact_premise": {"kind": "asset_theft"},
            "target_identity": {},
        },
        assumptions={"unit_loss": "1", "repetitions": 1},
    )
    severity = assess_severity(impact, preconditions_unprivileged=True)
    assert severity["finding_severity"]["label"] == "high"
    assert severity["rule_citation"].startswith("R2-")
    assert severity["policy_id"]
    claimed = dict(impact)
    claimed["deployment_claims"] = {"claimed": True, "verified": False}
    alt = assess_severity(claimed, preconditions_unprivileged=True)
    assert alt["ambiguities"]


def test_dedup_does_not_delete_from_store(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        first = seed_hypothesis(store, claim="reentrancy in withdraw", root_cause="call-before-zero")
        second = seed_hypothesis(
            store,
            claim="reentrancy in withdraw",
            root_cause="call-before-zero",
            attack_path=["withdraw"],
            origin="model_novel",
        )
        from ayran.evidence.load import load_hypothesis
        from ayran.evidence.service import dedup_check

        result = dedup_check(store, second["hypothesis_id"])
        assert result["deleted"] is False
        assert load_hypothesis(store, first["hypothesis_id"]) is not None
        assert load_hypothesis(store, second["hypothesis_id"]) is not None
    finally:
        store.close()
