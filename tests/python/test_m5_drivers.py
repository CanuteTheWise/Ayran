"""M5 lenses: distinguishable origins. R3 retarget of driver distinguishability.

R1: the templated model_native and adversarial_specialist drivers are deleted
(§5.1); model_novel authorship now flows only through hypotheses.remember
(see test_r1_hypothesis_remember.py).
"""

from __future__ import annotations

from pathlib import Path

from ayran.context.lenses import LENS_NAMES, LENS_ORIGINS, compile_lens_blocks
from ayran.evidence.service import remember
from m5_fixtures import CLUSTER, base_view


def test_drivers_are_distinguishable() -> None:
    view = base_view(
        knowledge_policy="graph_aware",
        target_first_completed=[CLUSTER],
        global_mechanisms=[{"id": "nod_01J0000000000000000000000A", "title": "reentrancy-pattern"}],
        global_incidents=[{"id": "nod_01J0000000000000000000000B", "title": "incident-x"}],
        contradictions=[{"id": "c1", "left": "spec:shares", "right": "code:shares", "kind": "spec-code"}],
        tool_runs=[
            {
                "tool_run_id": "trn_01J00000000000000000000001",
                "tool_name": "slither.analyze",
                "evidence_ceiling": "lead",
                "parse_status": "parsed",
            }
        ],
        maps={"attack_surface": {"entry_points": ["withdraw", "deposit"]}},
        coverage_cells=[],
    )
    blocks = compile_lens_blocks(view)
    assert set(blocks) == set(LENS_NAMES)
    origins = {name: LENS_ORIGINS[name] for name in LENS_NAMES}
    assert origins["first_principles"] == "model_novel"
    assert origins["precedent"] == "global_graph"
    assert origins["tool_signal"] == "tool"
    guidances = {name: blocks[name].guidance for name in LENS_NAMES if not blocks[name].suppressed}
    assert all(guidances[name] for name in guidances)
    assert len(set(guidances.values())) == len(guidances)


def test_model_novel_authorship_needs_no_anchors(tmp_path: Path) -> None:
    """Replaces the deleted model_native anchor-independence driver test: the
    remember() authorship path works from target material alone and never
    cites retrieved or tool anchors."""

    from m5_fixtures import open_store

    store = open_store(tmp_path)
    try:
        claim = (
            "withdraw settles msg.sender after an external call, so a fallback can "
            "double-withdraw against pooled deposits"
        )
        result = remember(
            store,
            origin="model_novel",
            claim=claim,
            attack_path=["enter withdraw()", "re-enter via fallback", "profit"],
            preconditions=[{"description": "attacker fallback contract", "attacker_can_create": True}],
            cluster_id="clus_01J00000000000000000000001",
            writer={"kind": "model", "id": "prime:sess-01j"},
            session="sess-01j",
        )
        assert result["accepted"] is True
        blob = result.get("claim", claim).lower() + " " + claim.lower()
        assert "historical" not in blob
        assert "slither" not in blob
        assert "first-principles" not in blob
    finally:
        store.close()


def test_global_graph_stops_when_blind() -> None:
    blocks = compile_lens_blocks(base_view(knowledge_policy="knowledge_blind"))
    assert blocks["precedent"].suppressed is True
    assert blocks["precedent"].stop_reason == "suppressed"
    assert LENS_ORIGINS["precedent"] == "global_graph"
