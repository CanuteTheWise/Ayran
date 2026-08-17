"""Data-flow: which functions read/write which state variables; taint sources to sinks."""

from __future__ import annotations

import json
from typing import Any

from ayran.context.ids import DEFAULT_CLUSTER_ID, DEFAULT_RUN_ID
from ayran.mapping.attack_surface import build_attack_surface
from ayran.mapping.types import call_edge, map_summary_node

PINNED = "2026-08-12T12:00:00Z"


def _prop(node: dict[str, Any], name: str) -> str:
    for item in node.get("properties") or []:
        if item.get("name") == name:
            return str(item.get("value") or "")
    return ""


def build_data_flow(
    *,
    cluster_id: str = DEFAULT_CLUSTER_ID,
    run_id: str = DEFAULT_RUN_ID,
    created_at: str = PINNED,
    source_text: str | None = None,
    source_units: list[dict[str, Any]] | None = None,
    slither_json: dict[str, Any] | None = None,
    locator: str = "target/src/Contract.sol",
) -> dict[str, Any]:
    surface = build_attack_surface(
        cluster_id=cluster_id,
        run_id=run_id,
        created_at=created_at,
        source_text=source_text,
        source_units=source_units,
        slither_json=slither_json,
        locator=locator,
    )
    blob = source_text or ""
    if source_units:
        blob = "\n".join(str(unit.get("source") or "") for unit in source_units)
    fn_nodes = [node for node in surface["nodes"] if node.get("node_type") == "Function"]
    state_nodes = [node for node in surface["nodes"] if node.get("node_type") == "StateVariable"]
    edges: list[dict[str, Any]] = []
    taint: list[dict[str, str]] = []
    for fn in fn_nodes:
        name = _prop(fn, "name")
        for state in state_nodes:
            var = _prop(state, "name")
            if not name or not var:
                continue
            if var in blob:
                edges.append(
                    call_edge(
                        source_id=str(fn["node_id"]),
                        target_id=str(state["node_id"]),
                        run_id=run_id,
                        created_at=created_at,
                        locator=locator,
                        edge_type="READS",
                    )
                )
                if f"{var} =" in blob or f"{var}=" in blob or f"{var}[" in blob:
                    edges.append(
                        call_edge(
                            source_id=str(fn["node_id"]),
                            target_id=str(state["node_id"]),
                            run_id=run_id,
                            created_at=created_at,
                            locator=locator,
                            edge_type="WRITES",
                        )
                    )
                    taint.append({"source": name, "sink": var, "kind": "state_write"})
    unique = {str(edge["edge_id"]): edge for edge in edges}
    edges = [unique[key] for key in sorted(unique)]
    payload = json.dumps(
        {"cluster_id": cluster_id, "taint": taint[:32], "edge_count": len(edges)},
        sort_keys=True,
        separators=(",", ":"),
    )
    summary = map_summary_node(
        map_type="DataFlowMap",
        cluster_id=cluster_id,
        run_id=run_id,
        created_at=created_at,
        payload=payload,
        extra={"edge_count": len(edges)},
    )
    return {
        "map_type": "data_flow",
        "cluster_id": cluster_id,
        "nodes": fn_nodes + state_nodes + [summary],
        "edges": edges,
        "taint": taint,
        "payload": json.loads(payload),
    }
