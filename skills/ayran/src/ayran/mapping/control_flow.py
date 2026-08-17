"""Function-level control-flow projection from source and Slither output."""

from __future__ import annotations

import json
from typing import Any

from ayran.context.ids import DEFAULT_CLUSTER_ID, DEFAULT_RUN_ID
from ayran.mapping.attack_surface import build_attack_surface
from ayran.mapping.types import call_edge, map_summary_node

PINNED = "2026-08-12T12:00:00Z"


def build_control_flow(
    *,
    cluster_id: str = DEFAULT_CLUSTER_ID,
    run_id: str = DEFAULT_RUN_ID,
    created_at: str = PINNED,
    source_text: str | None = None,
    slither_json: dict[str, Any] | None = None,
    source_units: list[dict[str, Any]] | None = None,
    locator: str = "target/src/Contract.sol",
) -> dict[str, Any]:
    surface = build_attack_surface(
        cluster_id=cluster_id,
        run_id=run_id,
        created_at=created_at,
        source_text=source_text,
        slither_json=slither_json,
        source_units=source_units,
        locator=locator,
    )
    fn_nodes = [node for node in surface["nodes"] if node.get("node_type") == "Function"]
    edges: list[dict[str, Any]] = []
    source_blob = source_text or ""
    if source_units:
        source_blob = "\n".join(str(unit.get("source") or "") for unit in source_units)
    names = [item["name"] for item in surface["functions"]]
    id_by_name = {
        next(
            (
                prop["value"]
                for prop in node.get("properties") or []
                if prop.get("name") == "name"
            ),
            "",
        ): node["node_id"]
        for node in fn_nodes
    }
    for caller in names:
        for callee in names:
            if caller == callee:
                continue
            if f"{callee}(" in source_blob:
                src = id_by_name.get(caller)
                dst = id_by_name.get(callee)
                if src and dst:
                    edges.append(
                        call_edge(
                            source_id=str(src),
                            target_id=str(dst),
                            run_id=run_id,
                            created_at=created_at,
                            locator=locator,
                            edge_type="CALLS",
                        )
                    )
    edges = sorted(edges, key=lambda row: str(row.get("edge_id")))
    # Dedup by edge_id
    unique = {str(edge["edge_id"]): edge for edge in edges}
    edges = [unique[key] for key in sorted(unique)]
    payload = json.dumps(
        {"cluster_id": cluster_id, "call_edges": len(edges), "functions": names},
        sort_keys=True,
        separators=(",", ":"),
    )
    summary = map_summary_node(
        map_type="ControlFlowMap",
        cluster_id=cluster_id,
        run_id=run_id,
        created_at=created_at,
        payload=payload,
        extra={"edge_count": len(edges)},
    )
    return {
        "map_type": "control_flow",
        "cluster_id": cluster_id,
        "nodes": [*fn_nodes, summary],
        "edges": edges,
        "payload": json.loads(payload),
    }
