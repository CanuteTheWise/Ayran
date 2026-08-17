"""Append ToolRun (and optional EvidenceArtifact) records through GraphStore.

The tools adapters never open the journal themselves.  The sidecar and tests
call these helpers, which are the only mutation path.
"""

from __future__ import annotations

from typing import Any

from ayran.api.validators import validate_contract
from ayran.graph.canonical import object_hash, utc_now
from ayran.graph.ids import new_id
from ayran.graph.recovery import GraphStore
from ayran.graph.types import AppendCommand, AppendItem
from ayran.tools.types import ADAPTER_VERSION, ZERO_HASH

ACTOR = {"kind": "tool", "id": "ayran.tools", "version": ADAPTER_VERSION}


def record_tool_run(
    store: GraphStore,
    tool_run: dict[str, Any],
    *,
    evidence: dict[str, Any] | None = None,
    config_hash: str = ZERO_HASH,
) -> dict[str, Any]:
    validate_contract("tool-run", tool_run)
    items = [AppendItem("tool-run@1.0.0", "tool_run.recorded", tool_run)]
    expected = {str(tool_run["tool_run_id"]): 0}
    if evidence is not None:
        validate_contract("evidence-artifact", evidence)
        items.insert(0, AppendItem("evidence-artifact@1.0.0", "evidence_artifact.recorded", evidence))
        expected[str(evidence["evidence_id"])] = 0
    command = AppendCommand(
        f"tool-run:{tool_run['tool_run_id']}",
        tuple(items),
        expected,
        ACTOR,
        config_hash,
        ADAPTER_VERSION,
        created_at=str(tool_run.get("created_at") or utc_now()),
    )
    return store.append(command)


def evidence_from_tool_run(
    tool_run: dict[str, Any],
    *,
    normalized_hash: str,
    size_bytes: int,
    grade: str,
) -> dict[str, Any]:
    evidence_ids = tool_run.get("normalized_evidence_ids") or []
    evidence_id = str(evidence_ids[0]) if evidence_ids else new_id("evd")
    created = str(tool_run.get("created_at") or utc_now())
    value: dict[str, Any] = {
        "schema_version": "1.0.0",
        "evidence_id": evidence_id,
        "created_at": created,
        "run_id": tool_run["run_id"],
        "target_identity": dict(tool_run["target_identity"]),
        "artifact_hash": normalized_hash,
        "size_bytes": size_bytes,
        "mime_type": "application/json",
        "producer": {"kind": "tool", "id": str(tool_run["tool_name"]), "version": ADAPTER_VERSION},
        "producer_version": ADAPTER_VERSION,
        "input_hashes": list(tool_run.get("input_hashes") or [tool_run["stdout_hash"]]),
        "config_hash": ZERO_HASH,
        "fork_identity_hash": tool_run.get("fork_identity_hash"),
        "raw_locator": "run/artifacts/raw.bin",
        "normalized_locator": "run/artifacts/normalized.json",
        "evidence_grade": grade if grade in {"lead", "supported", "observed", "defect_pinned", "validated"} else "lead",
        "trust_class": "deterministic_tool",
        "confidence": 1.0,
        "supports": [],
        "refutes": [],
        "redaction": {"profile": "default", "secret_scan_passed": True, "redacted": False},
        "reproduction": {
            "argv": list(tool_run["argv"]),
            "working_root": tool_run["working_root"],
            "environment_hash": tool_run["environment"][-1]["value"]
            if tool_run.get("environment")
            else ZERO_HASH,
            "expected_result_hash": normalized_hash,
        },
        "provenance": list(tool_run["provenance"]),
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": "rfc8785",
            "content_hash": ZERO_HASH,
            "excluded_fields": ["integrity.content_hash"],
        },
    }
    if value["evidence_grade"] == "validated":
        value["evidence_grade"] = "observed"
    value["integrity"]["content_hash"] = object_hash(value)
    return value
