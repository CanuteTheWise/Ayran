"""Corrective pass C1: smoke findings F1 (parsed outcome), F2 (identity), F3 (coverage)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from ayran.context.ids import content_id
from ayran.context.queries import OntologyQueries, snapshot_view
from ayran.evidence.errors import OBLIGATION_FORGERY_REJECTED
from ayran.gates.gate_b_mechanical import ForgeRunner
from ayran.graph.errors import CONTRACT_INVALID, NAMESPACE_MISMATCH
from ayran.graph.namespaces import TargetNamespace
from ayran.graph.recovery import GraphStore
from ayran.router.service import build_maps
from ayran.tools.adapters.foundry import parse_forge_coverage_summary

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
