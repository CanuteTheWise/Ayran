"""Append evidence objects through GraphStore.append only."""

from __future__ import annotations

from typing import Any

from ayran.api.validators import validate_contract
from ayran.context.contracts import graph_edge, graph_node, seal, typed_property
from ayran.context.ids import content_id
from ayran.evidence.actors import ACTOR_EVIDENCE
from ayran.evidence.state_machine import TransitionDecision
from ayran.evidence.types import CONFIG_HASH, RULE_VERSION
from ayran.graph.canonical import object_hash, utc_now
from ayran.graph.recovery import GraphStore
from ayran.graph.types import AppendCommand, AppendItem

ZERO_HASH = "sha256:" + "0" * 64


def _strip(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if not str(key).startswith("_")}


def persist_hypothesis_revision(
    store: GraphStore,
    hypothesis: dict[str, Any],
    *,
    actor: dict[str, Any],
    decision: TransitionDecision,
    event_id: str,
    created_at: str | None = None,
) -> dict[str, Any]:
    value = _strip(hypothesis)
    value["integrity"] = {
        "algorithm": "sha256",
        "canonicalization": "rfc8785",
        "content_hash": ZERO_HASH,
        "excluded_fields": ["integrity.content_hash"],
    }
    value["integrity"]["content_hash"] = object_hash(value)
    validate_contract("hypothesis", value)
    identifier = str(value["hypothesis_id"])
    current = store.projection.aggregate_revision(identifier)
    event_type = "hypothesis.recorded" if current == 0 else "hypothesis.revised"
    stamp = created_at or str(value.get("created_at") or utc_now())
    command = AppendCommand(
        f"hypothesis:{identifier}:{current + 1}:{event_id}",
        (
            AppendItem(
                "hypothesis@1.0.0",
                event_type,
                value,
                transition="retraction" if decision.kind == "retraction" else "snapshot",
                reason=decision.reason if decision.kind == "retraction" else None,
            ),
        ),
        {identifier: current},
        actor,
        CONFIG_HASH,
        RULE_VERSION,
        created_at=stamp,
    )
    return store.append(command)


def persist_contract(
    store: GraphStore,
    name: str,
    value: dict[str, Any],
    *,
    actor: dict[str, Any],
    event_stem: str,
) -> dict[str, Any]:
    payload = _strip(value)
    payload["integrity"] = {
        "algorithm": "sha256",
        "canonicalization": "rfc8785",
        "content_hash": ZERO_HASH,
        "excluded_fields": ["integrity.content_hash"],
    }
    payload["integrity"]["content_hash"] = object_hash(payload)
    validate_contract(name, payload)
    field = {"da-verdict": "verdict_id", "finding": "finding_id", "evidence-artifact": "evidence_id"}[
        name
    ]
    identifier = str(payload[field])
    current = store.projection.aggregate_revision(identifier)
    event_type = f"{event_stem}.recorded" if current == 0 else f"{event_stem}.revised"
    command = AppendCommand(
        f"{name}:{identifier}:{current + 1}",
        (AppendItem(f"{name}@1.0.0", event_type, payload),),
        {identifier: current},
        actor,
        CONFIG_HASH,
        RULE_VERSION,
        created_at=str(payload.get("created_at") or utc_now()),
    )
    return store.append(command)


def persist_runtime_node(store: GraphStore, node: dict[str, Any], *, actor: dict[str, Any]) -> dict[str, Any]:
    sealed = seal(dict(node))
    identifier = str(sealed["node_id"])
    current = store.projection.aggregate_revision(identifier)
    event_type = "node.created" if current == 0 else "node.revised"
    command = AppendCommand(
        f"evidence-node:{identifier}:{current + 1}",
        (AppendItem("graph-node@1.0.0", event_type, sealed),),
        {identifier: current},
        actor,
        CONFIG_HASH,
        RULE_VERSION,
        created_at=str(sealed.get("created_at") or utc_now()),
    )
    return store.append(command)


def persist_duplicate_edge(
    store: GraphStore,
    *,
    source_id: str,
    target_id: str,
    run_id: str,
    created_at: str,
    comparison: str,
) -> dict[str, Any]:
    source_node = _ensure_hypothesis_ref(store, source_id, run_id=run_id, created_at=created_at)
    target_node = _ensure_hypothesis_ref(store, target_id, run_id=run_id, created_at=created_at)
    edge_id = content_id("edg", "duplicates", source_id, target_id)
    if store.projection.aggregate_revision(edge_id):
        return {"appended": 0, "edge_id": edge_id}
    edge = graph_edge(
        edge_id=edge_id,
        edge_type="DUPLICATES",
        source_id=source_node,
        target_id=target_node,
        run_id=run_id,
        created_at=created_at,
        source_locator=f"dedup:{source_id}",
        properties=[
            typed_property("title", "duplicates"),
            typed_property("comparison", comparison[:512]),
            typed_property("source_hypothesis_id", source_id),
            typed_property("target_hypothesis_id", target_id),
        ],
    )
    sealed = seal(edge)
    command = AppendCommand(
        f"duplicate:{edge_id}",
        (AppendItem("graph-edge@1.0.0", "edge.created", sealed),),
        {edge_id: 0},
        ACTOR_EVIDENCE,
        CONFIG_HASH,
        RULE_VERSION,
        created_at=created_at,
    )
    return store.append(command)


def _ensure_hypothesis_ref(
    store: GraphStore,
    hypothesis_id: str,
    *,
    run_id: str,
    created_at: str,
) -> str:
    node_id = content_id("nod", "hyp-ref", hypothesis_id)
    if store.projection.aggregate_revision(node_id):
        return node_id
    persist_runtime_node(
        store,
        evidence_node(
            node_type="HypothesisRef",
            node_id=node_id,
            run_id=run_id,
            created_at=created_at,
            source_locator=f"hypothesis:{hypothesis_id}",
            properties={"title": "hypothesis-ref", "hypothesis_id": hypothesis_id},
        ),
        actor=ACTOR_EVIDENCE,
    )
    return node_id


def evidence_node(
    *,
    node_type: str,
    node_id: str,
    run_id: str,
    created_at: str,
    properties: dict[str, Any],
    source_locator: str,
    trust_class: str = "runtime_observation",
    evidence_grade: str = "supported",
) -> dict[str, Any]:
    typed = [
        typed_property(name, value, "boolean" if isinstance(value, bool) else "integer" if isinstance(value, int) else "string")
        if not isinstance(value, (dict, list))
        else typed_property(name, str(value), "string")
        for name, value in properties.items()
    ]
    return graph_node(
        node_id=node_id,
        node_type=node_type,
        run_id=run_id,
        created_at=created_at,
        source_locator=source_locator,
        properties=typed,
        trust_class=trust_class,
        evidence_grade=evidence_grade,
    )
