"""Typed RouterAction variants serialized onto the M0 RouterAction contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from ayran.context.contracts import ACTOR_ROUTER, default_target_identity, provenance_record
from ayran.context.ids import ROUTER_SEED_EVENT, ZERO_HASH, content_id
from ayran.graph.canonical import object_hash

ActionKind = Literal[
    "DispatchDriver",
    "LensUpdate",
    "InvokeTool",
    "InjectContext",
    "RequestSpecialist",
    "RecordCoverageUpdate",
    "RecordDeadEnd",
    "RecordOpenQuestion",
    "TriggerCompactionReconstruction",
    "EnterManualNext",
    "HaltRun",
    "ModelProposedInvestigation",
]

HANDLER_KIND = {
    "DispatchDriver": "service",
    "LensUpdate": "service",
    "InvokeTool": "adapter",
    "InjectContext": "service",
    "RequestSpecialist": "specialist",
    "RecordCoverageUpdate": "service",
    "RecordDeadEnd": "service",
    "RecordOpenQuestion": "service",
    "TriggerCompactionReconstruction": "service",
    "EnterManualNext": "service",
    "HaltRun": "service",
    "ModelProposedInvestigation": "model",
}

HANDLER_ID = {
    "DispatchDriver": "driver.dispatch",
    "LensUpdate": "lens.update",
    "InvokeTool": "tool.invoke",
    "InjectContext": "context.inject",
    "RequestSpecialist": "specialist.request",
    "RecordCoverageUpdate": "coverage.update",
    "RecordDeadEnd": "coverage.dead_end",
    "RecordOpenQuestion": "coverage.question",
    "TriggerCompactionReconstruction": "context.reconstruct",
    "EnterManualNext": "router.manual_next",
    "HaltRun": "router.halt",
    "ModelProposedInvestigation": "model.proposed_investigation",
}


@dataclass(frozen=True, slots=True)
class ActionRequest:
    kind: ActionKind
    cluster_id: str
    dedup_suffix: str
    budget_units: int = 0
    driver_name: str = ""
    capability_id: str = ""
    context_pack_id: str | None = None
    cell_id: str = ""
    new_state: str = ""
    approach: str = ""
    reason: str = ""
    question: str = ""
    role_id: str = ""
    blind_mode: bool = False
    payload_only: bool = False
    created_at: str = "2026-08-12T12:00:00Z"
    triggering_event_ids: tuple[str, ...] = ()
    priority: int = 0
    value_at_risk: int = 0
    urgency: int = 1
    novelty: int = 1
    run_id: str = "run_01J00000000000000000000001"
    target_identity: dict[str, Any] | None = None
    scope_id: str = "scp_01J00000000000000000000001"
    extra: str = ""


def priority_score(request: ActionRequest) -> int:
    efficiency = max(1, 20 - request.budget_units)
    raw = request.value_at_risk * request.urgency * request.novelty * efficiency
    return max(0, min(1000, raw))


def to_router_action(request: ActionRequest, *, status: str = "eligible") -> dict[str, Any]:
    created = request.created_at
    identity = request.target_identity or default_target_identity()
    dedup = f"{request.kind}:{request.cluster_id}:{request.dedup_suffix}"[:256]
    identifier = content_id("rta", dedup, created)
    raw_triggers = list(request.triggering_event_ids) or [ROUTER_SEED_EVENT]
    triggers = [item for item in raw_triggers if "_" in item and item.split("_", 1)[0].isalpha()]
    if not triggers:
        triggers = [ROUTER_SEED_EVENT]
    deadline = created[:-1] + "0Z" if created.endswith("Z") else created
    # Keep deadline a valid timestamp: add a deterministic one-hour offset via string pin.
    if created.endswith("Z") and "T" in created:
        deadline = created.split("T")[0] + "T13:00:00Z"
    stop = request.reason or request.kind
    pack_id = request.context_pack_id
    value: dict[str, Any] = {
        "schema_version": "1.0.0",
        "router_action_id": identifier,
        "created_at": created,
        "run_id": request.run_id,
        "target_identity": identity,
        "triggering_event_ids": triggers[:64],
        "policy_version": "1.0.0",
        "deduplication_key": re_key(dedup),
        "handler": {
            "kind": HANDLER_KIND[request.kind],
            "id": (
                f"driver.{request.driver_name}"
                if request.kind == "DispatchDriver" and request.driver_name
                else HANDLER_ID[request.kind]
            ),
            "version": "1.0.0",
        },
        "priority": request.priority or priority_score(request),
        "budget_effect": {
            "token_units": max(0, request.budget_units),
            "tool_seconds": 0 if request.kind != "InvokeTool" else 30,
            "wall_minutes": 5,
        },
        "dependencies": [],
        "authorization": {
            "decision": "deny" if request.payload_only else "allow",
            "scope_manifest_id": request.scope_id,
            "rule_ids": [],
            "decided_by": ACTOR_ROUTER,
            "decided_at": created,
            "reason": "payload_only" if request.payload_only else "in-scope deterministic route",
        },
        "status": "denied" if request.payload_only else status,
        "context_pack_id": pack_id,
        "owner": ACTOR_ROUTER,
        "deadline": deadline if _valid_ts(deadline) else created,
        "stop_condition": stop[:2048] if stop else request.kind,
        "emitted_operation_ids": [],
        "result_ids": [],
        "provenance": [provenance_record(created_at=created, material=identifier)],
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": "rfc8785",
            "content_hash": ZERO_HASH,
            "excluded_fields": ["integrity.content_hash"],
        },
    }
    if request.payload_only:
        value["authorization"]["decision"] = "deny"
        value["status"] = "denied"
        value["authorization"]["reason"] = "payload_only"
    value["integrity"]["content_hash"] = object_hash(value)
    return value


def re_key(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "_.:-" else "-" for ch in value)
    if not cleaned or not cleaned[0].isalnum():
        cleaned = "A" + cleaned
    return cleaned[:256]


def _valid_ts(value: str) -> bool:
    return len(value) >= 20 and value.endswith("Z") and "T" in value


def semantic_checksum(actions: list[dict[str, Any]]) -> str:
    from ayran.graph.canonical import canonical_hash

    rows = [
        {
            "handler": action.get("handler"),
            "deduplication_key": action.get("deduplication_key"),
            "priority": action.get("priority"),
            "budget_effect": action.get("budget_effect"),
            "status": action.get("status"),
            "stop_condition": action.get("stop_condition"),
            "kind": action.get("_kind"),
        }
        for action in actions
    ]
    return canonical_hash(rows)
