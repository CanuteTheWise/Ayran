"""M5 drivers: distinguishable origins. R1: the templated model_native and
adversarial_specialist drivers are deleted (§5.1); model_novel authorship now
flows only through hypotheses.remember (see test_r1_hypothesis_remember.py)."""

from __future__ import annotations

from pathlib import Path

from ayran.evidence.service import remember
from ayran.hypotheses.drivers import propose_all
from ayran.hypotheses.drivers.base import DRIVER_NAMES, DRIVER_ORIGINS
from m5_fixtures import base_view


def test_drivers_are_distinguishable() -> None:
    view = base_view(
        knowledge_policy="graph_aware",
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
    results = propose_all(view)
    assert set(results) == set(DRIVER_NAMES)
    origins = {name: results[name].origin for name in DRIVER_NAMES}
    assert origins == DRIVER_ORIGINS
    claims = {name: tuple(results[name].distinguishable_claims()) for name in DRIVER_NAMES}
    # Each origin must produce at least one claim, and the claim sets must not collapse to one.
    assert all(claims[name] for name in DRIVER_NAMES)
    unique_blobs = {" | ".join(claims[name]) for name in DRIVER_NAMES}
    assert len(unique_blobs) == len(DRIVER_NAMES)


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
    from ayran.hypotheses.drivers.global_graph import propose

    result = propose(base_view(knowledge_policy="knowledge_blind"))
    assert result.stop is True
    assert result.origin == "global_graph"
