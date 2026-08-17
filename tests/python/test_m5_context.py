"""M5 context compiler: labels, budgets, checksums, collapse reconstruction."""

from __future__ import annotations

from pathlib import Path

from ayran.context.compiler import RECONSTRUCTION_TITLES, compile_from_view, compile_with_injection
from ayran.context.labels import FACT_LABELS, NON_FACT_LABELS
from ayran.context.serialize import parse_checksum_footer
from ayran.context.view import reconstruction_fingerprint
from ayran.hypotheses.builders import build_hypothesis
from m5_fixtures import CLUSTER, CREATED, RUN_ID, TARGET_IDENTITY, base_view


def test_pack_fits_token_budget() -> None:
    view = base_view()
    pack = compile_from_view(view, token_budget=4000)
    assert pack["token_estimate"] <= 4000
    tiny = compile_from_view(view, token_budget=512)
    assert tiny["token_estimate"] <= 512
    assert set(RECONSTRUCTION_TITLES).issubset({section["title"] for section in tiny["sections"]})


def test_labeling_never_confuses_facts_and_assumptions() -> None:
    view = base_view(
        hypotheses=[
            build_hypothesis(
                origin="model_novel",
                claim="Assumed owner is unprivileged — this is an assumption not a fact.",
                cluster_id=CLUSTER,
                run_id=RUN_ID,
                created_at=CREATED,
                attack_path=["call setUnlock"],
                target_entities=[],
                preconditions=["owner key leaked"],
                trust_class="model_assumption",
                root_cause="assumption-owner",
                target_identity=TARGET_IDENTITY,
            )
        ]
    )
    pack = compile_from_view(view)
    by_title = {section["title"]: section for section in pack["sections"]}
    assert by_title["Known facts"]["classification"] in FACT_LABELS
    assert by_title["Assumptions"]["classification"] in NON_FACT_LABELS
    assert by_title["Assumptions"]["classification"] == "ASSUMPTION"
    assert "Assumed owner" in by_title["Assumptions"]["content"]
    assert by_title["Known facts"]["content"] != by_title["Assumptions"]["content"]
    historical = [section for section in pack["sections"] if section["classification"] == "HISTORICAL_REFERENCE"]
    assert historical == []


def test_checksum_is_deterministic() -> None:
    view = base_view()
    first = compile_from_view(view, created_at=CREATED)
    second = compile_from_view(view, created_at=CREATED)
    assert first["integrity"]["content_hash"] == second["integrity"]["content_hash"]
    assert first["context_pack_id"] == second["context_pack_id"]
    compiled = compile_with_injection(view, created_at=CREATED)
    footer = parse_checksum_footer(compiled["injection_text"])
    assert footer == first["integrity"]["content_hash"]
    assert "[POLICY]" in compiled["injection_text"]
    assert "[HYPOTHESIS]" in compiled["injection_text"]


def test_collapse_reconstruction_from_graph_view() -> None:
    view = base_view(
        hypotheses=[
            build_hypothesis(
                origin="model_novel",
                claim="Withdraw may skip an invariant.",
                cluster_id=CLUSTER,
                run_id=RUN_ID,
                created_at=CREATED,
                attack_path=["withdraw"],
                target_entities=[],
                preconditions=["unlocked"],
                target_identity=TARGET_IDENTITY,
            )
        ]
    )
    first = reconstruction_fingerprint(view)
    second = reconstruction_fingerprint(view)
    assert first == second
    pack = compile_from_view(view)
    titles = {section["title"] for section in pack["sections"]}
    assert set(RECONSTRUCTION_TITLES).issubset(titles)


def test_graph_aware_retrieved_context_is_historical() -> None:
    view = base_view(
        knowledge_policy="graph_aware",
        global_mechanisms=[{"id": "nod_01J00000000000000000000009", "title": "donation-inflation"}],
    )
    pack = compile_from_view(view)
    retrieved = [section for section in pack["sections"] if section["title"] == "Retrieved context"]
    assert retrieved
    assert retrieved[0]["classification"] == "HISTORICAL_REFERENCE"


def test_compile_from_empty_store(tmp_path: Path) -> None:
    from ayran.bridge.context_pack import compile_context_pack
    from m5_fixtures import open_store

    store = open_store(tmp_path)
    try:
        pack = compile_context_pack(store, run_id=RUN_ID, token_budget=800, created_at=CREATED)
        assert pack["run_id"] == RUN_ID
        assert pack["token_estimate"] <= 800
    finally:
        store.close()
