"""Orchestrate one capability invocation into a sealed ToolRun record.

Retries are explicit: each attempt is a new ToolRun.  The previous run is
linked only through provenance lineage (the ToolRun schema has no retries_from
field).  Exit code 0 never validates a finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from ayran.artifacts.store import ArtifactStore
from ayran.graph.canonical import object_hash
from ayran.graph.ids import new_id
from ayran.tools.base import bytes_hash, hashed_environment, mapping_of, unique_hashes
from ayran.tools.errors import PARSER_FAILED, ToolError
from ayran.tools.registry import CapabilityRegistry
from ayran.tools.types import (
    ADAPTER_VERSION,
    PARSER_VERSION,
    ZERO_HASH,
    ExecutionPolicy,
    ParseStatusName,
    RawRun,
)


@dataclass(slots=True)
class RunContext:
    run_id: str
    target_identity: dict[str, Any]
    artifact_store: ArtifactStore | None = None
    retries_from: str | None = None
    actor_id: str = "ayran.tools"


def _tool_version(raw: RawRun, parsed: BaseModel | None) -> str:
    extra_version = raw.extra.get("resolved_version") or raw.extra.get("tool_version")
    if isinstance(extra_version, str) and extra_version:
        return extra_version[:128]
    if parsed is not None:
        for attr in ("compiler_version", "forge_version", "slither_version"):
            value = getattr(parsed, attr, None)
            if isinstance(value, str) and value:
                return value[:128]
    return "unknown"


def _relative_work(raw: RawRun) -> str:
    if raw.working_copy:
        return "run/work"
    if raw.cwd:
        return "run/work"
    return "run/work"


def _store_bytes(store: ArtifactStore | None, payload: bytes, *, source: str) -> str | None:
    if store is None:
        return None
    if not payload:
        return None
    record = store.store(payload, media_type="application/octet-stream", source=source)
    digest = record.get("content_hash")
    return str(digest) if isinstance(digest, str) else None


def _parse_status(raw: RawRun, parsed: BaseModel | None, parse_error: str | None) -> ParseStatusName:
    if raw.timeout:
        return "failed"
    if parse_error:
        if "drift" in parse_error.lower():
            return "parser_drift"
        return "failed"
    if parsed is None:
        return "failed"
    if raw.stdout_truncated or raw.stderr_truncated:
        return "partial"
    return "parsed"


def build_tool_run(
    *,
    registry: CapabilityRegistry,
    capability_id: str,
    raw: RawRun,
    parsed: BaseModel | None,
    parse_error: str | None,
    context: RunContext,
    policy: ExecutionPolicy,
    env_map: dict[str, str],
) -> dict[str, Any]:
    resolved = registry.resolve_id(capability_id)
    manifest = registry.manifests[resolved]
    created = raw.ended_at
    tool_run_id = new_id("trn")
    parse_status = _parse_status(raw, parsed, parse_error)
    artifact_refs: list[str] = []
    stdout_ref = _store_bytes(context.artifact_store, raw.stdout, source="stdout")
    stderr_ref = _store_bytes(context.artifact_store, raw.stderr, source="stderr")
    for digest in (stdout_ref, stderr_ref, *raw.output_file_hashes.values()):
        if digest:
            artifact_refs.append(digest)
    normalized_json = b""
    evidence_ids: list[str] = []
    if parsed is not None:
        normalized_json = json.dumps(parsed.model_dump(mode="json"), separators=(",", ":"), ensure_ascii=True).encode()
        stored = _store_bytes(context.artifact_store, normalized_json, source="normalized")
        if stored:
            artifact_refs.append(stored)
        evidence_ids.append(new_id("evd"))
    provenance_raw = bytes_hash(raw.stdout + raw.stderr)
    lineage = []
    if context.retries_from:
        lineage.append(context.retries_from if context.retries_from.startswith("sha256:") else ZERO_HASH)
    value: dict[str, Any] = {
        "schema_version": "1.0.0",
        "tool_run_id": tool_run_id,
        "created_at": created,
        "run_id": context.run_id,
        "target_identity": dict(context.target_identity),
        "capability_id": resolved,
        "capability_version": str(manifest.get("version")),
        "adapter_version": ADAPTER_VERSION,
        "tool_name": str((manifest.get("triggers") or ["tool"])[0]).split(".", 1)[0],
        "tool_version": _tool_version(raw, parsed),
        "argv": [item[:512] for item in raw.argv[:128]],
        "environment": hashed_environment(env_map),
        "working_root": _relative_work(raw),
        "input_hashes": unique_hashes(raw.input_hashes)[:256],
        "seed": raw.extra.get("seed") if isinstance(raw.extra.get("seed"), int) else None,
        "fork_identity_hash": raw.extra.get("fork_identity_hash")
        if isinstance(raw.extra.get("fork_identity_hash"), str)
        else None,
        "limits": {
            "cpu": policy.cpu,
            "memory_mib": policy.memory_mib,
            "disk_mib": policy.disk_mib,
            "wall_seconds": policy.timeout_seconds,
            "network": policy.network
            if policy.network in {"none", "approved-api", "rpc-allowlist", "approved-source-fetch"}
            else "none",
        },
        "started_at": raw.started_at,
        "ended_at": raw.ended_at,
        "exit_code": raw.exit_code,
        "signal": raw.signal,
        "stdout_hash": raw.stdout_hash,
        "stderr_hash": raw.stderr_hash,
        "artifact_refs": unique_hashes(artifact_refs),
        "parse_status": parse_status,
        "parser_version": PARSER_VERSION,
        "normalized_evidence_ids": evidence_ids,
        "evidence_ceiling": manifest.get("evidence_ceiling"),
        "provenance": [
            {
                "provenance_id": new_id("prv"),
                "source_uri": "urn:ayran:tool-run",
                "source_version": ADAPTER_VERSION,
                "raw_hash": provenance_raw if provenance_raw.startswith("sha256:") else ZERO_HASH,
                "retrieved_at": created,
                "license_or_terms": "ayran-tool-run",
                "transformation_lineage": lineage,
            }
        ],
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": "rfc8785",
            "content_hash": ZERO_HASH,
            "excluded_fields": ["integrity.content_hash"],
        },
    }
    if not value["argv"]:
        value["argv"] = ["unknown"]
    if not value["tool_version"]:
        value["tool_version"] = "unknown"
    value["integrity"]["content_hash"] = object_hash(value)
    return value


async def run_capability(
    registry: CapabilityRegistry,
    capability_id: str,
    payload: dict[str, Any],
    *,
    policy: ExecutionPolicy,
    context: RunContext,
    require_available: bool = True,
) -> dict[str, Any]:
    adapter = registry.get_adapter(capability_id, require_available=require_available)
    request_type = getattr(adapter, "request_type", None)
    if request_type is None or request_type is BaseModel:
        raise ToolError("CONTRACT_INVALID", f"adapter {capability_id} has no request type")
    try:
        request = request_type.model_validate(payload)
    except ValidationError as error:
        raise ToolError("CONTRACT_INVALID", f"invalid tool input: {error}") from error
    env_map = {"PATH": registry.environment.path or "", "HOME": str(registry.environment.home or "")}
    if getattr(adapter, "experimental", False):
        env_map["AYRAN_EXPERIMENTAL"] = "true"
    try:
        raw = await adapter.run(request, policy)
    except ToolError:
        raise
    parsed: BaseModel | None = None
    parse_error: str | None = None
    try:
        if raw.timeout:
            parse_error = "timeout"
            raw.failure_type = raw.failure_type or "timeout"
        else:
            parsed = adapter.parse(raw)
            if raw.exit_code == 0 and parsed is None:
                raise ToolError(PARSER_FAILED, "parser returned no result")
    except ToolError as error:
        parse_error = error.message
        if raw.exit_code == 0 and not raw.timeout:
            # Successful exit with malformed output is a parse failure, not a success.
            raw.failure_type = raw.failure_type or "parser_drift"
    tool_run = build_tool_run(
        registry=registry,
        capability_id=capability_id,
        raw=raw,
        parsed=parsed,
        parse_error=parse_error,
        context=context,
        policy=policy,
        env_map=env_map,
    )
    return {
        "schema_version": "1.0.0",
        "tool_run": tool_run,
        "parsed": parsed.model_dump(mode="json") if parsed is not None else None,
        "failure_type": raw.failure_type,
        "parse_error": parse_error,
        "retries_from": context.retries_from,
        "privacy_audit": list(raw.privacy_audit),
        "raw_stdout_hash": raw.stdout_hash,
        "raw_stderr_hash": raw.stderr_hash,
    }


def policy_from_scope(
    *,
    manifest: dict[str, Any],
    allowed_paths: list[Path] | None = None,
    allowed_hosts: list[str] | None = None,
    allow_install: bool = False,
    offline: bool = False,
    scope_hash: str = ZERO_HASH,
    max_output_bytes: int | None = None,
) -> ExecutionPolicy:
    resources = mapping_of(manifest.get("resources"))
    return ExecutionPolicy(
        allowed_paths=tuple(allowed_paths or ()),
        network=str(resources.get("network") or "none"),
        allowed_hosts=tuple(allowed_hosts or ()),
        cpu=int(resources.get("cpu") or 1),
        memory_mib=int(resources.get("memory_mib") or 64),
        disk_mib=int(resources.get("disk_mib") or 0),
        timeout_seconds=int(manifest.get("timeout_seconds") or 60),
        max_output_bytes=max_output_bytes or 50 * 1024 * 1024,
        allow_install=allow_install,
        offline=offline,
        scope_hash=scope_hash,
    )
