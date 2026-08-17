"""Authority/privilege map: roles, ownership, access checks, unprotected mutations."""

from __future__ import annotations

import json
from typing import Any

from ayran.context.contracts import graph_node, typed_property
from ayran.context.ids import DEFAULT_CLUSTER_ID, DEFAULT_RUN_ID, content_id
from ayran.mapping.attack_surface import build_attack_surface
from ayran.mapping.types import call_edge, map_summary_node

PINNED = "2026-08-12T12:00:00Z"


def _prop(node: dict[str, Any], name: str) -> str:
    for item in node.get("properties") or []:
        if item.get("name") == name:
            return str(item.get("value") or "")
    return ""


def build_authority(
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
    roles = []
    if "onlyOwner" in blob or "owner" in blob.lower():
        roles.append("owner")
    if "onlyRole" in blob or "AccessControl" in blob:
        roles.append("role")
    role_nodes = [
        graph_node(
            node_id=content_id("nod", "role", role, cluster_id),
            node_type="Role",
            run_id=run_id,
            created_at=created_at,
            source_locator=locator,
            properties=[
                typed_property("canonical_key", f"role:{role}"),
                typed_property("name", role),
                typed_property("title", role),
            ],
        )
        for role in roles
    ]
    unprotected: list[str] = []
    edges: list[dict[str, Any]] = []
    for fn in fn_nodes:
        name = _prop(fn, "name")
        view = any(
            item.get("name") == "view" and item.get("value") is True
            for item in fn.get("properties") or []
        )
        guarded = any(token in blob for token in ("onlyOwner", "onlyRole", "require(msg.sender"))
        if not view and not guarded and _prop(fn, "visibility") in {"public", "external"}:
            unprotected.append(name)
        if guarded and role_nodes:
            edges.append(
                call_edge(
                    source_id=str(role_nodes[0]["node_id"]),
                    target_id=str(fn["node_id"]),
                    run_id=run_id,
                    created_at=created_at,
                    locator=locator,
                    edge_type="CONTROLS",
                )
            )
    unique = {str(edge["edge_id"]): edge for edge in edges}
    edges = [unique[key] for key in sorted(unique)]
    payload = json.dumps(
        {"cluster_id": cluster_id, "roles": roles, "unprotected": unprotected},
        sort_keys=True,
        separators=(",", ":"),
    )
    summary = map_summary_node(
        map_type="AuthorityMap",
        cluster_id=cluster_id,
        run_id=run_id,
        created_at=created_at,
        payload=payload,
        extra={"role_count": len(roles), "unprotected_count": len(unprotected)},
    )
    return {
        "map_type": "authority",
        "cluster_id": cluster_id,
        "nodes": fn_nodes + role_nodes + [summary],
        "edges": edges,
        "roles": roles,
        "unprotected": unprotected,
        "payload": json.loads(payload),
    }
