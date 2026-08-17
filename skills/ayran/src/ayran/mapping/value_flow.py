"""Value-transfer map: ETH, tokens, fees, concentration, asymmetric flows."""

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


def build_value_flow(
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
    flows: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for fn in fn_nodes:
        name = _prop(fn, "name")
        payable = any(
            item.get("name") == "payable" and item.get("value") is True
            for item in fn.get("properties") or []
        )
        snippet_hit = any(
            token in blob
            for token in (".transfer(", ".send(", "call{value", "msg.value", "safeTransfer")
        )
        if payable or snippet_hit:
            flows.append({"function": name, "kind": "eth_or_token", "asymmetric": payable and not snippet_hit})
            # Self-loop TRANSFERS marks a value-bearing function as a concentration point.
            edges.append(
                call_edge(
                    source_id=str(fn["node_id"]),
                    target_id=str(fn["node_id"]),
                    run_id=run_id,
                    created_at=created_at,
                    locator=locator,
                    edge_type="TRANSFERS",
                )
            )
    unique = {str(edge["edge_id"]): edge for edge in edges}
    edges = [unique[key] for key in sorted(unique)]
    payload = json.dumps(
        {
            "cluster_id": cluster_id,
            "flows": flows,
            "concentration_points": [item["function"] for item in flows],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    summary = map_summary_node(
        map_type="ValueFlowMap",
        cluster_id=cluster_id,
        run_id=run_id,
        created_at=created_at,
        payload=payload,
        extra={"flow_count": len(flows)},
    )
    return {
        "map_type": "value_flow",
        "cluster_id": cluster_id,
        "nodes": [*fn_nodes, summary],
        "edges": edges,
        "flows": flows,
        "payload": json.loads(payload),
    }
