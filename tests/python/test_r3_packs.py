"""R3 context-pack enrichment: census, money-map, coupled pairs, footer, writers (INV-5.8)."""

from __future__ import annotations

import pytest
from ayran.context.compiler import CompileError, compile_from_view
from ayran.context.contracts import graph_node, typed_property
from ayran.context.ids import content_id
from ayran.context.lenses import WRITE_EDGE_TYPES
from ayran.hypotheses.builders import build_hypothesis
from ayran.mapping.coverage import coverage_cell_record
from m5_fixtures import CLUSTER, CREATED, RUN_ID, TARGET_IDENTITY, base_view


def _fn(name: str) -> dict:
    return graph_node(
        node_id=content_id("nod", "function", name),
        node_type="Function",
        run_id=RUN_ID,
        created_at=CREATED,
        source_locator=f"target/{name}.sol",
        properties=[typed_property("name", name), typed_property("title", name)],
    )


def _state(name: str) -> dict:
    return graph_node(
        node_id=content_id("nod", "state", name),
        node_type="StateVariable",
        run_id=RUN_ID,
        created_at=CREATED,
        source_locator=f"target/{name}.sol",
        properties=[typed_property("name", name), typed_property("title", name)],
    )


def _edge(source_id: str, target_id: str, edge_type: str = "WRITES") -> dict:
    return {
        "edge_id": content_id("edg", edge_type.lower(), source_id, target_id),
        "edge_type": edge_type,
        "source_id": source_id,
        "target_id": target_id,
    }


def test_census_sections_rendered_and_arithmetic_fail_closed() -> None:
    withdraw = coverage_cell_record(
        coverage_cell_id=content_id("cov", CLUSTER, "entry_points", "withdraw"),
        dimension="entry_points:withdraw",
        cell_state="examined_no_issue",
        risk_score=10,
        run_id=RUN_ID,
        created_at=CREATED,
        target_identity=TARGET_IDENTITY,
    )
    view = base_view(
        maps={
            "attack_surface": {
                "entry_points": [
                    {"name": "withdraw", "payable": False},
                    {"name": "deposit", "payable": True, "value_flow": True},
                    {"name": "setUnlock", "payable": False},
                ]
            }
        },
        coverage_cells=[withdraw],
    )
    pack = compile_from_view(view, token_budget=8000)
    by_title = {section["title"]: section for section in pack["sections"]}
    census = by_title["Entry Point Census"]["content"]
    assert "census_total=M=3" in census
    assert "census_examined=N=1" in census
    assert "deposit" in census
    assert "setUnlock" in census
    assert "Lens: coverage" in by_title
    broken = coverage_cell_record(
        coverage_cell_id=content_id("cov", CLUSTER, "entry_points", "ghost"),
        dimension="entry_points:ghost",
        cell_state="examined_no_issue",
        risk_score=10,
        run_id=RUN_ID,
        created_at=CREATED,
        target_identity=TARGET_IDENTITY,
    )
    extra = coverage_cell_record(
        coverage_cell_id=content_id("cov", CLUSTER, "entry_points", "ghost2"),
        dimension="entry_points:ghost2",
        cell_state="residual_risk",
        risk_score=10,
        run_id=RUN_ID,
        created_at=CREATED,
        target_identity=TARGET_IDENTITY,
    )
    bad = base_view(
        maps={"attack_surface": {"entry_points": [{"name": "onlyOne"}]}},
        coverage_cells=[broken, extra],
    )
    with pytest.raises(CompileError, match="census arithmetic"):
        compile_from_view(bad, token_budget=8000)


def test_money_map_only_when_signaled_capped_200_lines() -> None:
    quiet = compile_from_view(base_view(), token_budget=8000)
    assert all(section["title"] != "Money-map summary" for section in quiet["sections"])
    flows = [{"function": f"f{index}", "kind": "eth_or_token", "asymmetric": True} for index in range(220)]
    view = base_view(
        maps={
            "attack_surface": {
                "entry_points": [{"name": "deposit", "payable": True, "value_flow": True}],
                "state_variables": ["balances"],
            },
            "value_flow": {
                "assets": ["ETH"],
                "totals": {"ETH": "1"},
                "flows": flows,
                "invariants": ["shares track assets"],
                "lifecycles": ["deposit/withdraw"],
                "cohorts": ["t0 depositors"],
            },
        }
    )
    pack = compile_from_view(view, token_budget=8000)
    money = next(section for section in pack["sections"] if section["title"] == "Money-map summary")
    lines = money["content"].split("\n")
    assert len(lines) <= 200
    if len(lines) == 200 or "(truncated at 200-line cap)" in money["content"]:
        assert lines[-1] == "(truncated at 200-line cap)" or "(truncated at 200-line cap)" in money["content"]
    assert "asymmetry table" in money["content"]
    assert "invariants:" in money["content"]
    assert "lifecycles:" in money["content"]
    assert "cohorts:" in money["content"]


def test_coupled_pair_inventory_rendered() -> None:
    mint = _fn("mint")
    burn = _fn("burn")
    supply = _state("totalSupply")
    view = base_view(
        nodes=[mint, burn, supply],
        edges=[
            _edge(mint["node_id"], supply["node_id"], "WRITES"),
            _edge(burn["node_id"], supply["node_id"], "WRITES"),
        ],
    )
    assert "WRITES" in WRITE_EDGE_TYPES
    pack = compile_from_view(view, token_budget=8000)
    coupled = next(
        section for section in pack["sections"] if section["title"] == "Coupled-state pair inventory"
    )
    assert "totalSupply" in coupled["content"]
    assert mint["node_id"] in coupled["content"]
    assert burn["node_id"] in coupled["content"]
    assert "updated by" in coupled["content"]


def test_advisory_footer_digest() -> None:
    view = base_view(
        payload_strikes={"tool_signal": 2},
        quarantined_sources=["tool_signal"],
        freeze_snapshots={CLUSTER: "sha256:" + "a" * 64},
        budget_state={"spent": 0, "tranche": 100, "reserve_released": False},
    )
    pack = compile_from_view(view, token_budget=8000)
    footer = next(section for section in pack["sections"] if section["title"] == "Advisory footer")
    assert "budget_remaining" in footer["content"]
    assert "strikes=" in footer["content"]
    assert "quarantined=" in footer["content"]
    assert "anchoring_freeze_count=1" in footer["content"]
    assert "first_principles=" in footer["content"]


def test_writer_identity_inline_per_node() -> None:
    item = build_hypothesis(
        origin="model_novel",
        claim="withdraw may skip an invariant",
        cluster_id=CLUSTER,
        run_id=RUN_ID,
        created_at=CREATED,
        attack_path=["withdraw"],
        target_entities=[],
        preconditions=["unlocked"],
        target_identity=TARGET_IDENTITY,
    )
    item["transition_history"][0]["actor"] = {"kind": "model", "id": "prime:sess-01j", "version": "1.0.0"}
    pack = compile_from_view(base_view(hypotheses=[item]), token_budget=8000)
    active = next(section for section in pack["sections"] if section["title"] == "Active hypotheses")
    assert "writer=model:prime:sess-01j" in active["content"]
    assert "origin=model_novel" in active["content"]
