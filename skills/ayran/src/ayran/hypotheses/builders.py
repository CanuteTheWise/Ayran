"""Hypothesis contract construction. Drivers never call the model."""

from __future__ import annotations

from typing import Any

from ayran.context.contracts import ACTOR_MODEL, default_target_identity, provenance_record
from ayran.context.ids import ZERO_HASH, content_id
from ayran.graph.canonical import object_hash

ORIGIN_BUDGET = {
    "model_novel": 25,
    "global_graph": 15,
    "contradiction": 15,
    "tool": 10,
    "coverage": 15,
    "specialist": 20,
}

ORIGIN_ACTOR = {
    "model_novel": {"kind": "model", "id": "ayran.driver.model_native", "version": "1.0.0"},
    "global_graph": {"kind": "service", "id": "ayran.driver.global_graph", "version": "1.0.0"},
    "contradiction": {"kind": "service", "id": "ayran.driver.contradiction", "version": "1.0.0"},
    "tool": {"kind": "tool", "id": "ayran.driver.tool", "version": "1.0.0"},
    "coverage": {"kind": "service", "id": "ayran.driver.coverage", "version": "1.0.0"},
    "specialist": {"kind": "specialist", "id": "ayran.driver.specialist", "version": "1.0.0"},
}


def canonical_triple(root_cause: str, state: str, attacker: str) -> str:
    return "|".join((root_cause.strip().lower(), state.strip().lower(), attacker.strip().lower()))


def hypothesis_id_for(origin: str, triple: str, cluster_id: str) -> str:
    return content_id("hyp", origin, cluster_id, triple)


def build_hypothesis(
    *,
    origin: str,
    claim: str,
    cluster_id: str,
    run_id: str,
    created_at: str,
    attack_path: list[str],
    target_entities: list[str],
    preconditions: list[str],
    impact_kind: str = "integrity_violation",
    impact_description: str = "Potential integrity or value impact under recorded assumptions",
    novelty: str = "unknown",
    required_falsifiers: list[str] | None = None,
    trust_class: str = "model_observation",
    root_cause: str = "",
    state: str = "",
    attacker: str = "unprivileged",
    target_identity: dict[str, Any] | None = None,
    next_evidence: str = "target-specific path and invariant",
) -> dict[str, Any]:
    triple = canonical_triple(root_cause or claim, state or cluster_id, attacker)
    identifier = hypothesis_id_for(origin, triple, cluster_id)
    actor = ORIGIN_ACTOR.get(origin, ACTOR_MODEL)
    units = ORIGIN_BUDGET.get(origin, 10)
    event_id = content_id("evt", identifier, "created")
    value: dict[str, Any] = {
        "schema_version": "1.0.0",
        "hypothesis_id": identifier,
        "created_at": created_at,
        "run_id": run_id,
        "target_identity": target_identity or default_target_identity(),
        "origin": origin,
        "claim": claim[:4096],
        "invariant_ids": [],
        "attack_path": [item[:512] for item in (attack_path or ["unspecified path"])[:64]],
        "target_entities": target_entities[:256] or [content_id("nod", cluster_id)],
        "preconditions": [
            {
                "description": item[:1024],
                "status": "unknown",
                "attacker_can_create": None,
            }
            for item in (preconditions or ["unspecified"])[:64]
        ],
        "impact_premise": {
            "kind": impact_kind,
            "description": impact_description[:2048],
            "upper_bound": None,
        },
        "priors": [
            {
                "source": "model"
                if origin == "model_novel"
                else "historical"
                if origin == "global_graph"
                else "tool"
                if origin == "tool"
                else "model",
                "confidence": 0.4,
            }
        ],
        "novelty": novelty,
        "required_falsifiers": [
            item[:1024] for item in (required_falsifiers or ["Show the claimed path is unreachable"])[:32]
        ],
        "budget": {
            "token_units": units * 100,
            "tool_seconds": 60,
            "wall_minutes": 15,
        },
        "parent_ids": [],
        "duplicate_candidate_ids": [],
        "status": "lead",
        "evidence_grade": "lead",
        "trust_class": trust_class,
        "confidence": 0.4,
        "transition_history": [
            {
                "from": None,
                "to": "lead",
                "event_id": event_id,
                "actor": actor,
                "at": created_at,
                "evidence_ids": [],
            }
        ],
        "provenance": [provenance_record(created_at=created_at, material=identifier)],
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": "rfc8785",
            "content_hash": ZERO_HASH,
            "excluded_fields": ["integrity.content_hash"],
        },
    }
    value["integrity"]["content_hash"] = object_hash(value)
    value["_triple"] = triple
    value["_next_evidence"] = next_evidence
    return value
