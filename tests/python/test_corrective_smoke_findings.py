"""Corrective pass C1+C2: smoke findings F1-F4 (parsed, identity, coverage, remember)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from ayran.context.contracts import default_target_identity
from ayran.context.ids import content_id
from ayran.context.queries import OntologyQueries, snapshot_view
from ayran.evidence.actors import ACTOR_EVIDENCE
from ayran.evidence.errors import OBLIGATION_FORGERY_REJECTED
from ayran.evidence.load import load_hypothesis, load_nodes_by_type, load_verdicts_for, node_props
from ayran.evidence.service import gate_b, poc_run, remember, transition
from ayran.gates.gate_b_mechanical import KRAIT_PASS, ForgeRunner, ScriptedRunner
from ayran.graph.errors import CONTRACT_INVALID, NAMESPACE_MISMATCH, GraphError
from ayran.graph.namespaces import TargetNamespace
from ayran.graph.recovery import GraphStore
from ayran.router.service import build_maps
from ayran.tools.adapters.foundry import parse_forge_coverage_summary
from m5_fixtures import CLUSTER
from m6_fixtures import (
    CHALLENGER_SUBMISSION_POC_WORTHY,
    GATE_B_EXECUTED,
    TRUE_DEFECT_EVIDENCE,
    challenger_gate_a,
    open_store,
    recorded_poc_for_executed,
)

_ = OBLIGATION_FORGERY_REJECTED  # import evidence before ayran.gates (package cycle)

TINY_VAULT = """
pragma solidity ^0.8.20;
contract TinyVault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""

COVERAGE_PATCHED_MULTI = """
| File                 | % Lines |
|----------------------|---------|
| src/PatchedVault.sol | 92.5%   |
| Total                | 40%     |
"""

COVERAGE_SINGLE = """
src/Only.sol 87%
"""

COVERAGE_TOTAL_ONLY = """
| File  | % Lines |
| Total | 64%     |
"""

PARSED_TEST_X: dict[str, Any] = {
    "tests": [
        {
            "name": "test_x()",
            "contract": "C",
            "status": "success",
            "gas": 123,
            "reason": None,
            "traces_present": False,
        }
    ],
    "compile_error": False,
    "passed": 1,
    "failed": 0,
    "skipped": 0,
}

TOOL_RUN_NO_STDOUT: dict[str, Any] = {
    "exit_code": 0,
    "limits": {},
    "stdout_hash": "sha256:" + "aa" * 32,
    "stderr_hash": "sha256:" + "bb" * 32,
}


def test_forge_runner_reads_parsed_outcome_not_stdout(tmp_path: Path) -> None:
    def stub_without_stdout(_kind: str, _payload: dict[str, Any]) -> dict[str, Any]:
        return {"tool_run": dict(TOOL_RUN_NO_STDOUT), "parsed": PARSED_TEST_X}

    clean = ForgeRunner(
        project_root=tmp_path,
        adapter_call=stub_without_stdout,
        measure_coverage=False,
    ).execute("replay", {})
    assert clean.passed_tests == ("test_x()",)
    assert clean.numeric_results == (123,)
    assert clean.exit_code == 0

    def stub_stdout_garbage(_kind: str, _payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_run": {**TOOL_RUN_NO_STDOUT, "stdout": "{this is not forge json"},
            "parsed": PARSED_TEST_X,
        }

    garbage = ForgeRunner(
        project_root=tmp_path,
        adapter_call=stub_stdout_garbage,
        measure_coverage=False,
    ).execute("replay", {})
    assert garbage.passed_tests == ("test_x()",)
    assert garbage.numeric_results == (123,)
    assert garbage.exit_code == 0


def test_build_maps_persists_cells_under_nondefault_identity(tmp_path: Path) -> None:
    identity = {
        "target_id": content_id("tgt", "corrective-pass-c1"),
        "source_tree_hash": "sha256:" + "c" * 64,
        "scope_id": content_id("scp", "corrective-pass-c1"),
        "commit": "c" * 40,
    }
    run_id = content_id("run", "corrective-pass-c1")
    namespace = TargetNamespace(
        tmp_path / "graph",
        run_id,
        identity,
        "sha256:" + "b" * 64,
        allow_unsafe_filesystem=True,
    )
    store = GraphStore(namespace.root, namespace.stream, allow_unsafe_filesystem=True)
    try:
        try:
            build_maps(store, "attack_surface", source_text=TINY_VAULT, persist=True)
        except Exception as error:
            code = getattr(error, "code", "")
            assert code not in {NAMESPACE_MISMATCH, CONTRACT_INVALID}, error
            raise
        view = snapshot_view(OntologyQueries(store=store), run_id=run_id)
        assert view.coverage_cells
        for cell in view.coverage_cells:
            cell_identity = cell.get("target_identity") or {}
            assert cell_identity.get("target_id") == identity["target_id"]
            assert cell_identity.get("scope_id") == identity["scope_id"]
            assert cell_identity.get("source_tree_hash") == identity["source_tree_hash"]
    finally:
        store.close()


def test_parse_forge_coverage_summary_variants() -> None:
    assert parse_forge_coverage_summary(
        COVERAGE_PATCHED_MULTI, patched_files=["src/PatchedVault.sol"]
    ) == pytest.approx(0.925)
    assert parse_forge_coverage_summary(COVERAGE_SINGLE) == pytest.approx(0.87)
    assert parse_forge_coverage_summary(COVERAGE_TOTAL_ONLY) == pytest.approx(0.64)
    assert parse_forge_coverage_summary("compiler exploded; not a table") is None


def test_patch_slot_carries_measured_coverage_via_seam(tmp_path: Path) -> None:
    def stub(kind: str, _payload: dict[str, Any]) -> Any:
        if kind == "coverage":
            return COVERAGE_PATCHED_MULTI
        return {"tool_run": dict(TOOL_RUN_NO_STDOUT), "parsed": PARSED_TEST_X}

    runner = ForgeRunner(
        project_root=tmp_path,
        adapter_call=stub,
        patch_files=({"path": "src/PatchedVault.sol", "content": "// patched\n"},),
    )
    results = {
        "replay": runner.execute("replay", {}),
        "patched": runner.execute("patched", {}),
        "revert_mutation": runner.execute("revert_mutation", {}),
    }
    assert results["patched"].coverage == pytest.approx(0.925)
    assert results["replay"].coverage is None
    assert results["revert_mutation"].coverage is None


C2_CLAIM = (
    "ReentrantVault.withdraw credits msg.sender only after the external call, so an "
    "attacker fallback can re-enter withdraw before balances are zeroed and drain "
    "the pool with two withdrawals for one deposit."
)


def _open_engagement_store(tmp_path: Path, identity: dict[str, Any], run_id: str) -> GraphStore:
    namespace = TargetNamespace(
        tmp_path / "graph",
        run_id,
        identity,
        "sha256:" + "b" * 64,
        allow_unsafe_filesystem=True,
    )
    return GraphStore(namespace.root, namespace.stream, allow_unsafe_filesystem=True)


def _walk_hunt_loop_to_defect_pinned(store: GraphStore) -> tuple[str, dict[str, Any]]:
    remembered = remember(
        store,
        origin="model_novel",
        claim=C2_CLAIM,
        attack_path=[
            "enter withdraw()",
            "re-enter via fallback before zeroing",
            "profit: double withdrawal",
        ],
        preconditions=[
            {"description": "attacker contract with payable fallback", "attacker_can_create": True},
            {"description": "vault holds pooled deposits", "attacker_can_create": False},
        ],
        violated_invariant="balances[msg.sender] is zeroed before any external call",
        cluster_id=CLUSTER,
        writer={"kind": "model", "id": "prime:c2-f4"},
        session="c2-f4",
    )
    hid = str(remembered["hypothesis_id"])
    transition(
        store,
        hid,
        "supported",
        evidence=TRUE_DEFECT_EVIDENCE,
        actor=ACTOR_EVIDENCE,
        cause="target-specific path and invariant",
    )
    verdict = challenger_gate_a(store, hid, dict(CHALLENGER_SUBMISSION_POC_WORTHY))
    assert verdict["verdict"] == "poc_worthy"
    poc = poc_run(store, hid, recorded=recorded_poc_for_executed(hid))
    assert poc["status"] == "succeeded"
    forged = gate_b(
        store,
        hid,
        obligations={"clean_replay": {"passed": True}},
        caller={"kind": "model", "id": "prime:c2-f4"},
    )
    assert forged.get("forgery_rejected") is True
    pinned = gate_b(
        store,
        hid,
        obligations=GATE_B_EXECUTED,
        poc_id=str(poc["poc_id"]),
        caller={"kind": "model", "id": "prime:c2-f4"},
        runner=ScriptedRunner(),
    )
    return hid, pinned


def _assert_carries_store_identity(obj: dict[str, Any], identity: dict[str, Any], label: str) -> None:
    carried: list[dict[str, Any]] = []
    raw = obj.get("target_identity")
    if isinstance(raw, dict):
        carried.append(raw)
    if isinstance(obj.get("properties"), list):
        props = node_props(obj)
        if props.get("target_id"):
            carried.append(
                {
                    "target_id": props.get("target_id"),
                    "scope_id": props.get("scope_id"),
                    "source_tree_hash": props.get("source_tree_hash"),
                    "commit": props.get("commit"),
                }
            )
        record_json = props.get("record_json")
        if record_json:
            sealed = json.loads(str(record_json))
            nested = sealed.get("target_identity")
            if isinstance(nested, dict):
                carried.append(nested)
    assert carried, f"{label} carried no target identity fields"
    for item in carried:
        assert item.get("target_id") == identity["target_id"], label
        assert item.get("scope_id") == identity["scope_id"], label
        assert item.get("source_tree_hash") == identity["source_tree_hash"], label


def test_real_identity_engagement_walk_reaches_defect_pinned(tmp_path: Path) -> None:
    identity = {
        "target_id": content_id("tgt", "corrective-pass-c2"),
        "source_tree_hash": "sha256:" + "c" * 64,
        "scope_id": content_id("scp", "corrective-pass-c2"),
        "commit": "c" * 40,
    }
    run_id = content_id("run", "corrective-pass-c2")
    store = _open_engagement_store(tmp_path, identity, run_id)
    try:
        try:
            hid, pinned = _walk_hunt_loop_to_defect_pinned(store)
        except GraphError as error:
            raise AssertionError(f"GraphError during real-identity hunt loop: {error}") from error
        hypothesis = load_hypothesis(store, hid)
        assert hypothesis is not None
        assert hypothesis["status"] == "defect_pinned"
        assert pinned["verdict"] == "defect_pinned"
        assert pinned["krait_stamp"] == KRAIT_PASS
        assert pinned.get("record", {}).get("schema_version") == "2.0.0"
        default_ids = {
            default_target_identity()["target_id"],
            default_target_identity()["scope_id"],
        }
        inspected = [("Hypothesis", hypothesis)]
        for verdict in load_verdicts_for(store, hid):
            inspected.append(("verdict", verdict))
        for node_type in ("PocRun", "GateBExecutionRecord"):
            nodes = load_nodes_by_type(store, node_type)
            assert nodes, f"expected persisted {node_type} nodes"
            for node in nodes:
                inspected.append((node_type, node))
        for label, obj in inspected:
            _assert_carries_store_identity(obj, identity, label)
            blob = json.dumps(obj, sort_keys=True)
            for leaked in default_ids:
                assert leaked not in blob, f"default identity leaked into {label}"
    finally:
        store.close()


def test_default_identity_stream_output_byte_stable(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        try:
            hid, pinned = _walk_hunt_loop_to_defect_pinned(store)
        except GraphError as error:
            raise AssertionError(f"GraphError during default-identity hunt loop: {error}") from error
        hypothesis = load_hypothesis(store, hid)
        assert hypothesis is not None
        assert hypothesis["status"] == "defect_pinned"
        assert pinned["krait_stamp"] == KRAIT_PASS
        assert hypothesis["target_identity"] == default_target_identity()
    finally:
        store.close()
