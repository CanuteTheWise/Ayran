"""Governed PoC workflow dispatched through the M4 Foundry adapter."""

from __future__ import annotations

import hashlib
from typing import Any

from ayran.context.ids import ZERO_HASH, content_id
from ayran.evidence.types import as_mapping

POC_STATUSES = ("pending", "executing", "succeeded", "failed", "flaky", "timeout")


def request_from_hypothesis(
    hypothesis: dict[str, Any],
    experiment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    spec = experiment or {}
    match = str(spec.get("match_test") or "test_exploit")
    return {
        "schema_version": "1.0.0",
        "poc_id": content_id("poc", str(hypothesis.get("hypothesis_id") or ""), match),
        "hypothesis_id": str(hypothesis.get("hypothesis_id") or ""),
        "status": "pending",
        "capability": "foundry.test",
        "match_test": match,
        "project_root": str(spec.get("project_root") or "fixtures/evidence/reentrant-vault"),
        "fork_block": spec.get("fork_block"),
        "seed": spec.get("seed"),
        "inputs": list(spec.get("inputs") or ["unprivileged attacker contract"]),
        "expected_positive": str(spec.get("expected_positive") or "attacker net increases"),
        "expected_negative": str(spec.get("expected_negative") or "control test does not steal"),
    }


def one_command(request: dict[str, Any], *, fork_url: str | None = None) -> str:
    parts = ["forge", "test", "--match-test", str(request.get("match_test") or "test_exploit"), "--json"]
    if fork_url:
        parts.extend(["--fork-url", fork_url])
    if request.get("fork_block") is not None:
        parts.extend(["--fork-block-number", str(request["fork_block"])])
    if request.get("seed") is not None:
        parts.extend(["--fuzz-seed", str(request["seed"])])
    return " ".join(parts)


def _hash_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def apply_recorded_result(request: dict[str, Any], recorded: dict[str, Any]) -> dict[str, Any]:
    """Windows-safe path: persist a recorded Foundry-shaped result without launching tools."""

    status = str(recorded.get("status") or "failed")
    if status not in POC_STATUSES:
        status = "failed"
    stdout = str(recorded.get("stdout") or "")
    result_hash = str(recorded.get("result_hash") or _hash_text(stdout or status))
    minimized = list(recorded.get("minimized_trace") or request.get("inputs") or [])
    command = str(recorded.get("one_command") or one_command(request))
    return {
        **request,
        "status": status,
        "result_hash": result_hash,
        "replay_hash": str(recorded.get("replay_hash") or result_hash),
        "replay_matched": recorded.get("replay_matched", True),
        "stdout_excerpt": stdout[:512] or status,
        "minimized_trace": minimized[:32],
        "one_command": command,
        "tool_run_id": str(recorded.get("tool_run_id") or content_id("trn", request["poc_id"], "recorded")),
        "evidence_ids": list(recorded.get("evidence_ids") or []),
        "fork_identity_hash": recorded.get("fork_identity_hash") or ZERO_HASH,
        "solc_version": str(recorded.get("solc_version") or "0.8.28"),
        "remappings": list(recorded.get("remappings") or []),
        "flaky": status == "flaky",
    }


def replay_recorded(original: dict[str, Any], replay: dict[str, Any] | None = None) -> dict[str, Any]:
    second = replay or original
    left = str(original.get("result_hash") or "")
    right = str(second.get("result_hash") or second.get("replay_hash") or left)
    matched = left == right and bool(left)
    status = "succeeded" if matched and original.get("status") == "succeeded" else "failed"
    return {
        **original,
        "status": status if matched else "failed",
        "replay_hash": right,
        "replay_matched": matched,
        "replayed": True,
    }


async def execute_foundry(request: dict[str, Any], *, recorded: dict[str, Any] | None = None) -> dict[str, Any]:
    """Dispatch Foundry when a live run is requested. Recorded results skip the adapter."""

    if recorded is not None:
        return apply_recorded_result(request, recorded)
    from ayran.tools.doctor import default_environment
    from ayran.tools.registry import CapabilityRegistry
    from ayran.tools.runner import RunContext, policy_from_scope, run_capability
    from ayran.tools.types import ALIAS_FOUNDRY

    registry = CapabilityRegistry(environment=default_environment())
    payload = {
        "project_root": request["project_root"],
        "match_test": request.get("match_test"),
        "json_output": True,
        "fork_block": request.get("fork_block"),
        "seed": request.get("seed"),
    }
    identity = {
        "target_id": "tgt_01J00000000000000000000001",
        "source_tree_hash": ZERO_HASH,
        "scope_id": "scp_01J00000000000000000000001",
    }
    result = await run_capability(
        registry,
        ALIAS_FOUNDRY,
        payload,
        policy=policy_from_scope(manifest=registry.manifests[registry.resolve_id(ALIAS_FOUNDRY)]),
        context=RunContext(run_id=str(request.get("run_id") or "run_01J00000000000000000000001"), target_identity=identity),
        require_available=True,
    )
    tool_run = as_mapping(result.get("tool_run"))
    parsed = as_mapping(result.get("parsed"))
    failed = int(parsed.get("failed") or 0)
    timeout = bool(tool_run.get("signal") == "timeout" or result.get("timeout"))
    if timeout:
        status = "timeout"
    elif failed == 0 and int(parsed.get("passed") or 0) > 0:
        status = "succeeded"
    else:
        status = "failed"
    stdout_hash = str(tool_run.get("stdout_hash") or ZERO_HASH)
    return apply_recorded_result(
        {**request, "run_id": tool_run.get("run_id")},
        {
            "status": status,
            "result_hash": stdout_hash,
            "replay_hash": stdout_hash,
            "stdout": status,
            "tool_run_id": str(tool_run.get("tool_run_id") or ""),
            "one_command": one_command(request),
            "fork_identity_hash": tool_run.get("fork_identity_hash"),
            "evidence_ids": list(tool_run.get("normalized_evidence_ids") or []),
        },
    )
