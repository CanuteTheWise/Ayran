"""M9 sealed A0-A7 evaluation: leakage, metrics, gates, immutability."""

from __future__ import annotations

from pathlib import Path

import pytest
from ayran.evaluation.arms import ARM_SEQUENCE, order_for_seed
from ayran.evaluation.controller import run_session
from ayran.evaluation.errors import MANIFEST_IMMUTABLE, SEALED_LEAKAGE, EvaluationError
from ayran.evaluation.leakage import scan_leakage
from ayran.evaluation.metrics import discover, score_arm
from ayran.evaluation.results import load_manifest, write_manifest
from ayran.evaluation.sealed import built_in_catalog, dump_catalog, opaque_id


def test_opaque_ids_are_not_descriptive() -> None:
    catalog = built_in_catalog()
    assert len(catalog) == 9
    for item in catalog:
        assert item.fixture_id.startswith("sev_")
        assert "reentrancy" not in item.fixture_id
        assert "vault" not in item.fixture_id
        assert item.content_hash.startswith("sha256:")


def test_contamination_groups_keep_cei_together() -> None:
    cei = [item.fixture_id for item in built_in_catalog() if item.contamination_group == "grp_cei"]
    assert len(cei) >= 2


def test_arm_order_alternates_across_fixed_seeds() -> None:
    assert order_for_seed(7) == ARM_SEQUENCE
    assert order_for_seed(13) == tuple(reversed(ARM_SEQUENCE))
    assert order_for_seed(21)[0] == "A0"
    assert order_for_seed(21) != ARM_SEQUENCE


def test_a5_improves_on_a0_recall(tmp_path: Path) -> None:
    fixtures = built_in_catalog()
    a0, _, _, _ = score_arm("A0", fixtures)
    a5, _, found, fps = score_arm("A5", fixtures)
    assert a5.severity_weighted_recall > a0.severity_weighted_recall
    assert a5.precision + 1e-9 >= a0.precision * 0.95
    assert found
    assert "fp_slither_reentrancy_view" not in fps


def test_same_inputs_same_metrics(tmp_path: Path) -> None:
    first = run_session(results_root=tmp_path / "r1", seeds=(7,))
    second = run_session(results_root=tmp_path / "r2", seeds=(7,))
    assert first.content_hash == second.content_hash
    assert [run.result_hash for run in first.arms] == [run.result_hash for run in second.arms]


def test_full_session_gate_and_comparisons(tmp_path: Path) -> None:
    manifest = run_session(results_root=tmp_path / "results")
    assert len(manifest.arms) == 8 * 3
    assert manifest.gate.zero_critical_failures is True
    assert manifest.gate.non_inferior_to_a0 is True
    assert manifest.gate.improved_over_a0 is True
    assert manifest.gate.release_ready is True
    assert manifest.model_invoked is False
    assert "target_only" in manifest.comparisons
    assert "external_hound" not in manifest.comparisons
    assert manifest.leakage["clean"] is True
    assert manifest.adjudication
    assert manifest.agreement
    loaded = load_manifest(manifest.session_id, results_root=tmp_path / "results")
    assert loaded.content_hash == manifest.content_hash


def test_manifest_is_immutable(tmp_path: Path) -> None:
    manifest = run_session(results_root=tmp_path / "results", seeds=(7,), arms=("A0",))
    mutated = manifest.model_copy(update={"content_hash": "sha256:" + "0" * 64})
    with pytest.raises(EvaluationError) as raised:
        write_manifest(mutated, results_root=tmp_path / "results")
    assert raised.value.code == MANIFEST_IMMUTABLE


def test_leakage_scan_rejects_fixture_id_in_knowledge(tmp_path: Path) -> None:
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    (knowledge / "poison.json").write_text(opaque_id("s2"), encoding="utf-8")
    with pytest.raises(EvaluationError) as raised:
        scan_leakage(knowledge_root=knowledge, learning_root=tmp_path / "learning")
    assert raised.value.code == SEALED_LEAKAGE


def test_a0_discovers_no_validated_reentrancy() -> None:
    fixtures = [item for item in built_in_catalog() if item.scenario == "known_vulnerable"]
    assert fixtures
    assert discover("A0", fixtures[0]) == []
    assert discover("A5", fixtures[0])


def test_cli_eval_arm_and_results(tmp_path: Path) -> None:
    from m7_fixtures import invoke, payload

    results_root = tmp_path / "results"
    code, output = invoke(
        ["eval", "run", "--arm", "A0", "--seed", "7", "--results-root", str(results_root)]
    )
    assert code == 0, output
    body = payload(output)["result"]
    session = body["session_id"]
    code, output = invoke(["eval", "results", "--session", session, "--results-root", str(results_root)])
    assert code == 0, output
    shown = payload(output)["result"]
    assert shown["session_id"] == session
    code, output = invoke(["eval", "adjudicate", "--session", session, "--results-root", str(results_root)])
    assert code == 0, output


def test_dump_catalog_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "catalog.json"
    dump_catalog(path)
    assert path.is_file()
