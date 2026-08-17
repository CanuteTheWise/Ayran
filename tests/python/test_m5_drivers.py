"""M5 six drivers: distinguishable origins, model-native without anchors."""

from __future__ import annotations

from ayran.hypotheses.drivers import propose_all
from ayran.hypotheses.drivers.base import DRIVER_NAMES, DRIVER_ORIGINS
from m5_fixtures import VAULT_SOURCE, base_view


def test_six_drivers_are_distinguishable() -> None:
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
    unique_blobs = { " | ".join(claims[name]) for name in DRIVER_NAMES }
    assert len(unique_blobs) == 6


def test_model_native_works_without_retrieved_or_tool_anchors() -> None:
    view = base_view(
        knowledge_policy="target_only",
        global_mechanisms=[{"id": "x", "title": "should-be-ignored"}],
        tool_runs=[{"tool_run_id": "trn_01J00000000000000000000001", "tool_name": "slither.analyze"}],
        source_units=[{"kind": "source", "name": "Vault", "source": VAULT_SOURCE}],
    )
    from ayran.hypotheses.drivers.model_native import propose

    result = propose(view)
    assert result.origin == "model_novel"
    assert result.hypotheses
    blob = " ".join(result.distinguishable_claims()).lower()
    assert "historical" not in blob
    assert "slither" not in blob
    assert "withdraw" in blob or "deposit" in blob or "first-principles" in blob


def test_global_graph_stops_when_blind() -> None:
    from ayran.hypotheses.drivers.global_graph import propose

    result = propose(base_view(knowledge_policy="knowledge_blind"))
    assert result.stop is True
    assert result.origin == "global_graph"
