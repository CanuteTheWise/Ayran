"""M4 WSL ext4 tests: real solc/forge/slither detection and fixture runs."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from ayran.tools.doctor import default_environment, tools_doctor
from ayran.tools.registry import CapabilityRegistry
from ayran.tools.runner import RunContext, policy_from_scope, run_capability
from ayran.tools.types import (
    ALIAS_FOUNDRY,
    ALIAS_SLITHER,
    ALIAS_SOLC,
    Environment,
)

pytestmark = pytest.mark.wsl_ext4

ROOT = Path(__file__).resolve().parents[2]
PROJECTS = ROOT / "fixtures" / "tool-projects"
RUN_ID = "run_01J00000000000000000000001"
TARGET_IDENTITY = {
    "target_id": "tgt_01J00000000000000000000001",
    "source_tree_hash": "sha256:" + "d" * 64,
    "scope_id": "scp_01J00000000000000000000001",
    "commit": "1" * 40,
}


def _registry() -> CapabilityRegistry:
    env = default_environment()
    env.probe_http = False
    return CapabilityRegistry(ROOT / "capabilities", environment=env, probe_on_load=True)


def test_wsl_detects_solc_forge_slither() -> None:
    registry = _registry()
    by_alias = {item.alias: item for item in registry.list_capabilities()}
    solc = by_alias[ALIAS_SOLC]
    foundry = by_alias[ALIAS_FOUNDRY]
    slither = by_alias[ALIAS_SLITHER]
    assert solc.status == "available"
    assert foundry.status == "available"
    assert slither.status == "available"
    assert solc.version_observed is not None and solc.version_observed.startswith("0.8.")
    assert foundry.version_observed is not None and foundry.version_observed.startswith("1.7.")
    assert slither.version_observed == "0.11.5"


def test_wsl_solc_compiles_minimal_contract() -> None:
    registry = _registry()
    source = PROJECTS / "solc-minimal" / "Hello.sol"
    result = asyncio.run(
        run_capability(
            registry,
            ALIAS_SOLC,
            {"source_paths": [str(source)], "combined_json": True},
            policy=policy_from_scope(manifest=registry.manifests[registry.resolve_id(ALIAS_SOLC)]),
            context=RunContext(run_id=RUN_ID, target_identity=TARGET_IDENTITY),
        )
    )
    parsed = result["parsed"]
    assert parsed is not None
    assert parsed["contracts"]
    assert result["tool_run"]["input_hashes"]
    assert result["tool_run"]["stdout_hash"].startswith("sha256:")
    assert result["tool_run"]["parse_status"] in {"parsed", "partial"}


def test_wsl_foundry_classifies_pass_and_fail() -> None:
    registry = _registry()
    project = PROJECTS / "foundry-minimal"
    result = asyncio.run(
        run_capability(
            registry,
            ALIAS_FOUNDRY,
            {"project_root": str(project), "json_output": True},
            policy=policy_from_scope(manifest=registry.manifests[registry.resolve_id(ALIAS_FOUNDRY)]),
            context=RunContext(run_id=RUN_ID, target_identity=TARGET_IDENTITY),
        )
    )
    parsed = result["parsed"]
    assert parsed is not None
    statuses = {item["name"]: item["status"] for item in parsed["tests"]}
    assert statuses.get("testPass()") == "pass" or any(item["status"] == "pass" for item in parsed["tests"])
    assert statuses.get("testMismatch()") == "fail" or any(item["status"] == "fail" for item in parsed["tests"])
    assert parsed["compile_error"] is False


def test_wsl_slither_false_positive_and_lead_ceiling() -> None:
    registry = _registry()
    source = PROJECTS / "slither-fp" / "ViewReentrancy.sol"
    result = asyncio.run(
        run_capability(
            registry,
            ALIAS_SLITHER,
            {"source_paths": [str(source)]},
            policy=policy_from_scope(manifest=registry.manifests[registry.resolve_id(ALIAS_SLITHER)]),
            context=RunContext(run_id=RUN_ID, target_identity=TARGET_IDENTITY),
        )
    )
    parsed = result["parsed"]
    assert parsed is not None
    assert parsed["evidence_ceiling"] == "lead"
    assert result["tool_run"]["evidence_ceiling"] == "lead"
    assert parsed["alerts"]
    assert any(alert.get("spans") for alert in parsed["alerts"])


def test_wsl_doctor_reports_available_or_degrades() -> None:
    registry = _registry()
    report = asyncio.run(tools_doctor(registry))
    executable = [
        item
        for item in report["capabilities"]
        if item["alias"] in {ALIAS_SOLC, ALIAS_FOUNDRY, ALIAS_SLITHER}
    ]
    assert all(item["status"] == "available" for item in executable)
    missing = os.environ.get("AYRAN_M4_DROP_TOOL")
    if missing:
        env = Environment(path="/nonexistent", allowed_binary_roots=(), probe_http=False)
        dropped = CapabilityRegistry(ROOT / "capabilities", environment=env, probe_on_load=True)
        degraded = asyncio.run(tools_doctor(dropped))
        assert degraded["doctor_status"] == "degraded"
        assert degraded["errors"]
