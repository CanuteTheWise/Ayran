"""Authorized actor kinds per hypothesis state (blueprint §5.2)."""

from __future__ import annotations

from typing import Any

ACTOR_EVIDENCE = {"kind": "service", "id": "ayran.evidence", "version": "1.0.0"}
ACTOR_GATE_A = {"kind": "gate", "id": "ayran.gate_a", "version": "1.0.0"}
ACTOR_GATE_B = {"kind": "gate", "id": "ayran.gate_b", "version": "1.0.0"}
ACTOR_DEDUP = {"kind": "service", "id": "ayran.dedup", "version": "1.0.0"}
ACTOR_POC = {"kind": "service", "id": "ayran.poc", "version": "1.0.0"}
ACTOR_FINDING = {"kind": "service", "id": "ayran.finding", "version": "1.0.0"}
ACTOR_REPORT = {"kind": "service", "id": "ayran.report", "version": "1.0.0"}
ACTOR_ADAPTER = {"kind": "tool", "id": "ayran.tools.foundry", "version": "1.0.0"}
ACTOR_ROUTER = {"kind": "router", "id": "ayran.router", "version": "1.0.0"}
ACTOR_HUMAN = {"kind": "human", "id": "ayran.operator", "version": "1.0.0"}

# Target-state authorized kinds. The transition actor.kind must be in this set.
AUTHORIZED_KINDS: dict[str, frozenset[str]] = {
    "lead": frozenset({"model", "specialist", "tool", "human"}),
    "supported": frozenset({"service"}),
    "poc_worthy": frozenset({"gate"}),
    "observed": frozenset({"tool", "service"}),
    "defect_pinned": frozenset({"gate"}),
    "validated": frozenset({"service"}),
    "falsified": frozenset({"gate", "service"}),
    "needs_missing_fact": frozenset({"gate", "router", "service"}),
    "needs_reformulation": frozenset({"gate", "router", "service"}),
    "parked": frozenset({"router", "human"}),
    "duplicate_known_issue": frozenset({"service"}),
    "reported": frozenset({"service"}),
}


def actor_kind(actor: dict[str, Any]) -> str:
    return str(actor.get("kind") or "")


def actor_is_authorized(actor: dict[str, Any], target_state: str) -> bool:
    allowed = AUTHORIZED_KINDS.get(target_state, frozenset())
    return actor_kind(actor) in allowed
